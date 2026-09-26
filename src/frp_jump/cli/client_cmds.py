"""`frp-jump client ...` -- enroll this device, run its tunnel agent, and
self-serve device/connection management (no server-side admin action
needed for any of it once you have one enrolled device)."""

from __future__ import annotations

import os
import time
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.table import Table

from frp_jump.agent import enroll as enroll_mod
from frp_jump.agent import hosts, poller, service_install
from frp_jump.agent.state import Profile, load, request_wake, save
from frp_jump.common.settings import Settings
from frp_jump.driver.base import ServiceProtocol
from frp_jump.driver.frp.binaries import ensure_installed
from frp_jump.driver.frp.driver import FrpDriver

app = typer.Typer(
    help="Enroll this device, run its tunnel agent, and manage your own devices/connections."
)
console = Console()

# Ports auto-classified as SSH -- everything else defaults to a plain TCP
# tunnel unless --ssh forces it. See connect_cmd's help for the rationale
# (Occam's razor: there is no functional difference frp-jump enforces
# between "tcp" and "http"/anything else, see driver/base.py).
_SSH_PORTS = frozenset({22, 2222})

try:
    _AGENT_VERSION = version("frp-jump")
except PackageNotFoundError:
    # Running from a source checkout without an installed/editable package
    # (e.g. `uv run python -m frp_jump.cli.client_cmds`) -- not a real
    # deployment, so a fixed fallback is fine rather than failing the
    # whole command.
    _AGENT_VERSION = "dev"


def _ssh_config_path(settings: Settings) -> Path:
    return settings.ssh_config_path or (Path.home() / ".ssh" / "config")


def _port_range(settings: Settings) -> range:
    return range(settings.agent_local_port_range_start, settings.agent_local_port_range_end + 1)


def _require_state(settings: Settings):
    state = load(settings.data_dir)
    if state is None:
        console.print(
            "[red]not enrolled[/red] -- run "
            "[bold]frp-jump-client enroll <url> <token-or-keyfile>[/bold] first"
        )
        raise typer.Exit(1)
    return state


def _settings_for_service_ops(*, user_service: bool, system_user: str | None = None) -> Settings:
    """`Settings()`, with `data_dir` corrected for `sudo` -- shared by
    `enroll` (before writing state) and `install-service` (before
    checking for it), so both agree on where state lives when run via
    sudo as a real person's own account rather than a genuine root login.
    Without this, `sudo`'s default `env_reset`/`secure_path` policy sets
    `$HOME` to root's home, so a plain `Settings()` here would look in
    `/root` even though `enroll` (run unprivileged, the whole point of
    this two-step flow) wrote state under the invoking person's own home
    -- see `service_install.resolve_target_home`'s docstring.

    ``system_user`` takes priority over the sudo-aware resolution above --
    it points at a dedicated, isolated account's own state directory
    instead (see `service_install.ensure_system_user`), creating that
    account if it doesn't exist yet."""
    settings = Settings()
    if system_user:
        if os.geteuid() != 0:
            console.print("[red]--system-user requires root[/red] -- rerun with sudo")
            raise typer.Exit(1)
        settings.data_dir = service_install.ensure_system_user(system_user)
    elif os.geteuid() == 0 and not user_service and "FRP_JUMP_DATA_DIR" not in os.environ:
        home, _ = service_install.resolve_target_home()
        settings.data_dir = home / ".local" / "share" / "frp-jump"
    return settings


def _make_driver(settings: Settings) -> FrpDriver:
    binaries = ensure_installed(settings.data_dir / "bin", version=settings.frp_version)
    return FrpDriver(
        binary=binaries.frpc,
        state_dir=settings.data_dir / "frpc",
        admin_port=settings.frpc_admin_port,
        fallback_timeout_ms=settings.xtcp_fallback_timeout_ms,
    )


def _make_driver_with_retry(settings: Settings) -> FrpDriver:
    """Same as `_make_driver`, but a network hiccup while downloading the
    (first-run-only) frp binaries is not fatal -- print and back off/retry
    like `run_forever`'s own sync loop, instead of exiting and leaving a
    systemd `Restart=` policy to keep bouncing the whole service. A
    genuinely unfixable problem (unsupported CPU architecture, a corrupt
    download) still raises immediately -- retrying that forever would
    just hide it behind an endless, silent loop."""
    backoff = poller.BACKOFF_INITIAL_SECONDS
    while True:
        try:
            return _make_driver(settings)
        except httpx.HTTPError as exc:
            console.print(
                f"[yellow]could not download frp ({exc}) -- retrying in {backoff:.0f}s[/yellow]"
            )
            time.sleep(backoff)
            backoff = min(backoff * 2, poller.BACKOFF_MAX_SECONDS)


def _classify_protocol(port: int, *, force_ssh: bool) -> ServiceProtocol:
    if force_ssh or port in _SSH_PORTS:
        return ServiceProtocol.SSH
    return ServiceProtocol.TCP


# How long `connect` waits, after waking the daemon, to see the local port
# it allocates -- generous enough for a slow device's frpc restart, short
# enough that a `run` daemon that isn't actually running (or is down) fails
# fast with a clear "not applied yet" instead of hanging indefinitely.
_LOCAL_PORT_WAIT_SECONDS = 10.0
_LOCAL_PORT_POLL_INTERVAL_SECONDS = 0.5


def _wait_for_local_port(data_dir: Path, grant_id: str) -> int | None:
    deadline = time.monotonic() + _LOCAL_PORT_WAIT_SECONDS
    while time.monotonic() < deadline:
        state = load(data_dir)
        if state is not None and grant_id in state.local_ports:
            return state.local_ports[grant_id]
        time.sleep(_LOCAL_PORT_POLL_INTERVAL_SECONDS)
    return None


def _parse_device_port(target: str) -> tuple[str, int]:
    device, sep, port_str = target.rpartition(":")
    if not sep:
        raise typer.BadParameter(f"expected DEVICE:PORT, e.g. wb01:22 -- got {target!r}")
    try:
        port = int(port_str)
    except ValueError:
        raise typer.BadParameter(f"{port_str!r} is not a valid port number") from None
    return device, port


def _resolve_keypair(path: Path) -> tuple[Path, str]:
    """Given either a private key path or its `.pub` sibling, return
    (private_key_path, public_key_text) -- shared by every command that
    needs to *prove possession* of a key, not just read its public half."""
    identity_path = path.with_suffix("") if path.suffix == ".pub" else path
    pub_path = identity_path.with_name(identity_path.name + ".pub")
    if not pub_path.is_file():
        console.print(
            f"[red]could not find {pub_path}[/red] -- pass the path to your "
            "*private* key, e.g. ~/.ssh/id_ed25519"
        )
        raise typer.Exit(1)
    public_key = pub_path.read_text()
    if not public_key.strip():
        console.print(f"[red]{pub_path} is empty[/red]")
        raise typer.Exit(1)
    return identity_path, public_key


@app.command("enroll")
def enroll_cmd(
    control_url: str = typer.Argument(
        ..., help="Base URL of the frp-jump server, e.g. https://tunnel.example.com"
    ),
    token_or_keyfile: str = typer.Argument(
        ...,
        metavar="TOKEN_OR_KEYFILE",
        help="Either a one-time enroll token, or the path to your registered "
        "SSH private key (e.g. ~/.ssh/id_ed25519) -- whichever an admin gave you.",
    ),
    name: str | None = typer.Option(
        None,
        "--name",
        help="This device's name. Required when enrolling with a key; for a "
        "token, only needed if the token doesn't already fix one -- the "
        "command you were given tells you which.",
    ),
    user_service: bool = typer.Option(
        False,
        "--user",
        help="If run as root, install the systemd service under your own "
        "account afterwards instead of system-wide. Ignored when not root.",
    ),
    system_user: str | None = typer.Option(
        None,
        "--system-user",
        help="Create (if missing) and enroll as a dedicated, unprivileged "
        "system account with this name, instead of your own account or "
        "root -- e.g. --system-user frp-jump-client. Requires root; "
        "mutually exclusive with --user.",
    ),
) -> None:
    """Trade a one-time enroll token, or your own registered SSH key, for
    this device's identity.

    This is always the first command run on a new device. An admin either
    registered your SSH key (`frp-jump-server users add-key`) -- pass the
    matching *private* key's path here -- or gave you a one-time token
    instead. Every device after your first is self-service either way, no
    admin action needed (`frp-jump-client devices add-token`).

    Run as root, this also installs and starts the systemd service right
    away; otherwise it prints the `install-service` command to run next.

    Examples:

        frp-jump-client enroll https://tunnel.example.com abc123...

        frp-jump-client enroll https://tunnel.example.com ~/.ssh/id_ed25519 --name laptop

        sudo frp-jump-client enroll https://tunnel.example.com abc123... \\
            --name laptop --system-user frp-jump-client
    """
    if user_service and system_user:
        console.print("[red]--user and --system-user are mutually exclusive[/red]")
        raise typer.Exit(1)
    settings = _settings_for_service_ops(user_service=user_service, system_user=system_user)
    keyfile_path = Path(token_or_keyfile).expanduser()

    try:
        if keyfile_path.is_file():
            if not name:
                console.print("[red]--name is required when enrolling with a key[/red]")
                raise typer.Exit(1)
            identity_path, public_key = _resolve_keypair(keyfile_path)
            state = enroll_mod.enroll_by_key(
                control_url=control_url,
                identity_path=identity_path,
                public_key=public_key,
                name=name,
                data_dir=settings.data_dir,
            )
        else:
            state = enroll_mod.enroll(
                control_url=control_url,
                token=token_or_keyfile,
                data_dir=settings.data_dir,
                requested_name=name,
            )
    except enroll_mod.EnrollError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    if system_user:
        service_install.chown_tree(settings.data_dir, system_user)

    console.print(
        f"[green]Enrolled[/green] as [bold]{state.device_name}[/bold] ({state.device_id})"
    )

    if os.geteuid() == 0:
        try:
            unit_path = service_install.install(user=user_service, system_user=system_user)
        except service_install.ServiceInstallError as exc:
            console.print(f"[yellow]could not install the service:[/yellow] {exc}")
            console.print(
                "Run [bold]frp-jump-client run[/bold] manually, or retry with "
                "[bold]frp-jump-client install-service[/bold]."
            )
        else:
            console.print(f"[green]Service installed and started[/green] ({unit_path}).")
    else:
        # `sudo` resets PATH to its own secure_path, which never includes a
        # per-user install location like ~/.local/bin -- "sudo
        # frp-jump-client ..." then fails with "command not found" even
        # though it works fine unprivileged (a real case hit in testing).
        # Print the resolved absolute path for the sudo variant specifically
        # so copy-pasting the hint always works.
        try:
            exec_path = service_install.resolve_exec_path()
        except service_install.ServiceInstallError:
            exec_path = "frp-jump-client"
        console.print(
            f"Next: [bold]sudo {exec_path} install-service[/bold] (system-wide), "
            "[bold]frp-jump-client install-service --user[/bold] (your own account), "
            "or just [bold]frp-jump-client run[/bold] in the foreground."
        )


@app.command("install-service")
def install_service_cmd(
    user: bool = typer.Option(
        False,
        "--user",
        help="Install under your own account instead of system-wide (no root needed).",
    ),
    system_user: str | None = typer.Option(
        None,
        "--system-user",
        help="Run as a dedicated, unprivileged system account with this name "
        "(created if missing) instead of your own account or root -- e.g. "
        "--system-user frp-jump-client. Requires root; mutually exclusive "
        "with --user. If you haven't enrolled yet, use `enroll --system-user "
        "<name>` instead, so enrollment itself also lands in that account.",
    ),
) -> None:
    """Install and enable the systemd service that keeps `run` going across
    reboots. Safe to rerun any time, e.g. after upgrading the binary -- it
    refreshes the unit to point at wherever `frp-jump-client` currently is.

    If you installed with `pip install --user`/pipx and `sudo
    frp-jump-client install-service` fails with "command not found", sudo's
    own PATH doesn't include your user install location -- use the full
    path instead: `sudo $(which frp-jump-client) install-service`.

    `--user` only keeps running while you have an active login session --
    it stops the moment you log out, unless you also run `sudo loginctl
    enable-linger $(whoami)` once to let it keep running regardless.
    Without `--user` (the default, system-wide), this doesn't apply -- it
    runs regardless of who's logged in. `--system-user` doesn't apply
    either way -- it's an isolated account of its own, not tied to any
    login session.

    Examples:

        sudo frp-jump-client install-service

        sudo $(which frp-jump-client) install-service

        frp-jump-client install-service --user

        sudo frp-jump-client install-service --system-user frp-jump-client
    """
    if user and system_user:
        console.print("[red]--user and --system-user are mutually exclusive[/red]")
        raise typer.Exit(1)
    settings = _settings_for_service_ops(user_service=user, system_user=system_user)
    _require_state(settings)
    try:
        unit_path = service_install.install(user=user, system_user=system_user)
    except service_install.ServiceInstallError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    console.print(f"[green]Installed and started[/green] ({unit_path}).")
    if user:
        console.print(
            "[yellow]Note:[/yellow] a --user service stops when you log out, unless you "
            "also run [bold]sudo loginctl enable-linger $(whoami)[/bold] once."
        )


@app.command("set-key")
def set_key_cmd(
    keyfile: Path = typer.Argument(
        ...,
        help="Path to your new SSH private key, e.g. ~/.ssh/id_ed25519_new -- "
        "proves you actually hold it before rotating.",
    ),
) -> None:
    """Rotate your own SSH key -- e.g. you generated a new one. Signs a
    server-issued challenge with the new key to prove you hold it before
    the rotation takes effect; updates every device you own, no separate
    action needed on any of them.

    Example:

        frp-jump-client set-key ~/.ssh/id_ed25519_new
    """
    settings = Settings()
    state = _require_state(settings)
    identity_path, public_key = _resolve_keypair(keyfile.expanduser())
    try:
        poller.set_key(state, identity_path, public_key)
    except poller.SyncError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    console.print("[green]Key updated.[/green]")


@app.command("run")
def run_cmd(
    agent_version: str = typer.Option(_AGENT_VERSION, help="Reported to the server on heartbeats."),
) -> None:
    """Run the agent loop in the foreground: heartbeat, pull desired state,
    apply it to the local frpc process and ~/.ssh/config, repeat.

    Meant to be wrapped by systemd (see `install-service`), not run by hand
    day-to-day -- but running it in a terminal is the easiest way to watch
    what it's doing while setting things up.

    Example:

        frp-jump-client run
    """
    settings = Settings()
    state = _require_state(settings)
    driver = _make_driver_with_retry(settings)

    console.print(
        f"[green]agent running[/green] as {state.device_name}, "
        f"polling every {settings.agent_poll_interval_seconds}s"
    )
    poller.run_forever(
        state,
        driver,
        data_dir=settings.data_dir,
        ssh_config_path=_ssh_config_path(settings),
        poll_interval_seconds=settings.agent_poll_interval_seconds,
        port_range=_port_range(settings),
        agent_version=agent_version,
    )


@app.command("status")
def status_cmd() -> None:
    """Show this device's identity and what it currently exposes/consumes.

    Example:

        frp-jump-client status
    """
    settings = Settings()
    state = _require_state(settings)

    console.print(f"Device: [bold]{state.device_name}[/bold] ({state.device_id})")
    console.print(f"Server: {state.control_url}   Relay: {state.relay_addr}:{state.relay_port}")

    try:
        remote = poller.fetch_desired_state(state)
    except poller.SyncError as exc:
        console.print(f"[yellow]could not reach server: {exc}[/yellow]")
        raise typer.Exit(1) from exc

    console.print("\n[bold]Exposed[/bold] -- other devices can reach these ports on you")
    exposed = Table()
    exposed.add_column("Port")
    for g in remote["exposed"]:
        exposed.add_row(str(g["target_port"]))
    console.print(exposed)

    profile_by_target = {
        (p.device_name, p.target_port): name for name, p in state.profiles.items()
    }
    console.print("[bold]Consumed[/bold] -- ports you connected to, via `connect`")
    consumed = Table()
    consumed.add_column("Profile")
    consumed.add_column("Device")
    consumed.add_column("Port")
    consumed.add_column("Protocol")
    consumed.add_column("Local address")
    for g in remote["consumed"]:
        local_port = state.local_ports.get(g["grant_id"])
        addr = f"127.0.0.1:{local_port}" if local_port else "not yet synced"
        profile_name = profile_by_target.get((g["exposer_device_name"], g["target_port"]), "—")
        consumed.add_row(
            profile_name, g["exposer_device_name"], str(g["target_port"]), g["protocol"], addr
        )
    console.print(consumed)


@app.command("doctor")
def doctor_cmd() -> None:
    """Sanity-check this device: enrolled? frp binary present? server reachable?

    Run this first whenever something seems wrong -- `run`/`connect`/etc.
    all assume these basics already work.

    Example:

        frp-jump-client doctor
    """
    settings = Settings()
    ok = True

    state = load(settings.data_dir)
    if state is None:
        console.print("[red]✗ not enrolled[/red]")
        raise typer.Exit(1)
    console.print(f"[green]✓[/green] enrolled as {state.device_name}")

    frpc_path = settings.data_dir / "bin" / "frpc"
    if frpc_path.exists():
        console.print(f"[green]✓[/green] frpc present at {frpc_path}")
    else:
        console.print("[yellow]✗[/yellow] frpc not installed yet (installed on first `client run`)")
        ok = False

    try:
        poller.send_heartbeat(state, agent_version="doctor")
        console.print("[green]✓[/green] server reachable, heartbeat accepted")
    except poller.SyncError as exc:
        console.print(f"[red]✗[/red] server heartbeat failed: {exc}")
        ok = False

    if not ok:
        raise typer.Exit(1)


@app.command("connect")
def connect_cmd(
    target: str = typer.Argument(
        ...,
        help="DEVICE:PORT to connect to, e.g. wb01:22 (device from `frp-jump-client "
        "devices list`) -- or the name of an existing profile (from `profiles "
        "list`) to reconnect it without retyping device/port.",
    ),
    ssh: bool = typer.Option(
        False,
        "--ssh",
        help="Treat this as SSH (writes an ~/.ssh/config Host entry) even though "
        "the port isn't one of the well-known SSH ports (22, 2222).",
    ),
    local_port: int | None = typer.Option(
        None,
        "--local-port",
        help="Pin the local port to bind, instead of letting one be picked for "
        "you automatically. Must be free on this device right now.",
    ),
    as_name: str | None = typer.Option(
        None,
        "--as",
        help="Save this connection as a named profile (used by `disconnect`/"
        "`profiles` and, for ssh, as the `ssh <name>` host alias). Defaults to "
        "the device's own name, or DEVICE-PORT if that name is already taken "
        "by a different port on the same device -- set this explicitly for a "
        "name of your own choosing. Only applies when connecting via "
        "DEVICE:PORT, not when reconnecting an existing profile by name.",
    ),
) -> None:
    """Wire this device up to consume a port on another device you own, and
    save it as a named profile for next time.

    Ports 22 and 2222 are treated as SSH automatically (an ~/.ssh/config
    `Host` entry is written for them); anything else is a plain TCP
    tunnel unless --ssh forces SSH classification for a non-standard port.
    There's no other protocol distinction to make -- a TCP tunnel carries
    whatever's actually running on the port (a web UI, MQTT, anything)
    identically either way. The local port this binds is only ever
    reachable from this device itself (127.0.0.1) -- never from your LAN
    or the internet.

    Safe to re-run -- connecting again reuses the existing connection.
    Wakes a running `frp-jump-client run` immediately instead of waiting
    out its normal poll interval, and waits (up to 10s) to show the local
    port it picks; if nothing shows up in that time, `run` likely isn't
    running yet or hasn't caught up -- `status` will show it once it has.

    Examples:

        frp-jump-client connect wb01:22
        # ssh -- 22 is a well-known ssh port, no --ssh needed

        frp-jump-client connect wb01:2222 --ssh
        # a non-standard ssh port -- --ssh forces ssh classification

        frp-jump-client connect wb01:80
        # a plain tcp tunnel, e.g. a web UI or MQTT broker

        frp-jump-client connect wb01:22 --local-port 2222
        # pin the local port instead of picking a free one automatically

        frp-jump-client connect wb01-web
        # reconnect an existing profile by name
    """
    settings = Settings()
    state = _require_state(settings)

    if local_port is not None and not poller.is_bindable(local_port):
        console.print(f"[red]port {local_port} is not free on this device right now[/red]")
        raise typer.Exit(1)

    if ":" in target:
        device, port = _parse_device_port(target)
        if as_name is not None:
            if not hosts.is_safe_alias(as_name):
                console.print(
                    f"[red]{as_name!r} is not a valid profile name[/red] -- use 1-63 "
                    "characters, letters/digits/underscore/hyphen, starting with a "
                    "letter or digit (it may end up as an ssh_config Host alias)"
                )
                raise typer.Exit(1)
            profile_name = as_name
        else:
            # Default to the device's own name (the common case: one port
            # per device) -- but that name is already someone else's if
            # you're connecting to a *second* port on the same device, so
            # disambiguate automatically instead of making every
            # multi-port connection require --as up front.
            profile_name = device
            existing = state.profiles.get(profile_name)
            if existing is not None and (existing.device_name, existing.target_port) != (
                device,
                port,
            ):
                profile_name = f"{device}-{port}"

        existing = state.profiles.get(profile_name)
        if existing is not None and (existing.device_name, existing.target_port) != (
            device,
            port,
        ):
            console.print(
                f"[red]{profile_name!r} is already used[/red] for "
                f"{existing.device_name}:{existing.target_port} -- pick a different --as "
                "name, or `profiles delete` it first to repurpose it"
            )
            raise typer.Exit(1)
    else:
        if as_name is not None:
            console.print("[red]--as only applies when connecting via DEVICE:PORT[/red]")
            raise typer.Exit(1)
        profile = state.profiles.get(target)
        if profile is None:
            console.print(f"[red]no profile named[/red] {target!r}.")
            console.print(
                "\nIf you meant to connect to a device, specify a port:\n\n"
                "  frp-jump-client connect DEVICE:22               # ssh (well-known port)\n"
                "  frp-jump-client connect DEVICE:2222 --ssh       # non-standard ssh port\n"
                "  frp-jump-client connect DEVICE:80               # a plain tcp tunnel\n"
                "  frp-jump-client connect DEVICE:22 --local-port 2222  # pin the local port\n\n"
                "If --local-port is omitted, a free one is picked automatically. See "
                "[bold]frp-jump-client profiles list[/bold] for saved profiles."
            )
            raise typer.Exit(1)
        device, port, profile_name = profile.device_name, profile.target_port, target

    protocol_enum = _classify_protocol(port, force_ssh=ssh)

    try:
        result = poller.connect(state, device_name=device, target_port=port, protocol=protocol_enum)
    except poller.SyncError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    state.profiles[profile_name] = Profile(device_name=device, target_port=port)
    if local_port is not None:
        state.local_ports[result["grant_id"]] = local_port
    save(settings.data_dir, state)
    request_wake(settings.data_dir)

    local_bound = _wait_for_local_port(settings.data_dir, result["grant_id"])
    if local_bound is not None:
        console.print(
            f"[green]Connected[/green] to {device}:{port} as [bold]{profile_name}[/bold] "
            f"-- 127.0.0.1:{local_bound}"
            + (f" (ssh {profile_name})" if protocol_enum == ServiceProtocol.SSH else "")
        )
    else:
        console.print(
            f"[green]Connected[/green] to {device}:{port} as [bold]{profile_name}[/bold] "
            "-- no local port yet; is `frp-jump-client run` active? Check `status` shortly."
        )


@app.command("disconnect")
def disconnect_cmd(
    target: str = typer.Argument(
        ...,
        help="Local name from `connect --as` (or the device name, if you "
        "didn't set one) -- or DEVICE:PORT directly, from the Device/Port "
        "columns in `status`, if the profile is missing or you never set one.",
    ),
    from_device: str | None = typer.Option(
        None,
        "--from",
        help="Disconnect as a different one of your own devices instead of "
        "this one -- e.g. you noticed a connection left up elsewhere in "
        "`frp-jump-client devices list` / `frp-jump-server devices list`. "
        "That other device picks this up on its own next poll cycle, not "
        "instantly -- only this device's own daemon gets woken immediately.",
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip the confirmation prompt when using --from."
    ),
) -> None:
    """Drop a connection previously made with `connect`. Only tears down
    the tunnel -- the saved profile (if any) stays put, so `connect
    <name>` brings it right back later. Use `profiles delete` to actually
    remove the saved shortcut.

    Examples:

        frp-jump-client disconnect wb01

        frp-jump-client disconnect wb01:22

        frp-jump-client disconnect wb01:22 --from other-laptop
    """
    settings = Settings()
    state = _require_state(settings)

    profile = state.profiles.get(target)
    if profile is not None:
        device_name, target_port = profile.device_name, profile.target_port
    else:
        try:
            device_name, target_port = _parse_device_port(target)
        except typer.BadParameter:
            console.print(
                f"[red]no such connection[/red] {target!r} -- see "
                "[bold]frp-jump-client status[/bold] for the Device/Port to pass "
                "as DEVICE:PORT"
            )
            raise typer.Exit(1) from None

    if from_device is not None and not yes:
        if not typer.confirm(
            f"Disconnect {device_name}:{target_port} as {from_device!r} (a different device)?"
        ):
            raise typer.Exit(0)

    try:
        poller.disconnect(
            state,
            device_name=device_name,
            target_port=target_port,
            consumer_device_name=from_device,
        )
    except poller.NotConnectedError:
        pass  # already gone server-side -- the desired end state is reached either way
    except poller.SyncError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    request_wake(settings.data_dir)
    console.print(f"[green]Disconnected[/green] {device_name}:{target_port}.")


devices_app = typer.Typer(
    help="Manage your own devices -- list, add via token, delete, disable/enable."
)
app.add_typer(devices_app, name="devices")


@devices_app.command("add-token")
def devices_add_token_cmd(
    name: str | None = typer.Option(
        None,
        "--name",
        help="Fix the new device's name now. Leave unset to let the new "
        "device pick its own name at enroll time (`enroll ... --name`).",
    ),
) -> None:
    """Mint a one-time enroll token for one more device of your own. If
    that device has its own SSH key, it can skip tokens entirely and
    enroll straight from it instead (see `enroll`'s help).

    Examples:

        frp-jump-client devices add-token

        frp-jump-client devices add-token --name laptop
    """
    settings = Settings()
    state = _require_state(settings)
    try:
        issued = poller.add_device(state, device_name_hint=name)
    except poller.SyncError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    command = f"frp-jump-client enroll {state.control_url} {issued['token']}"
    if not name:
        command += " --name <pick-a-name>"
    console.print("Run this on the new device to enroll it (shown once):")
    console.print(f"[bold]{command}[/bold]")


@devices_app.command("list")
def devices_list_cmd() -> None:
    """List every device you own (yours and any you've added).

    Example:

        frp-jump-client devices list
    """
    settings = Settings()
    state = _require_state(settings)
    try:
        devices = poller.list_devices(state)
    except poller.SyncError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    table = Table(title="Your devices")
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("Last seen")
    for d in devices:
        status_text = "active" if d["enabled"] else "[yellow]disabled[/yellow]"
        table.add_row(d["name"], status_text, d["last_seen_at"] or "never")
    console.print(table)


@devices_app.command("delete")
def devices_delete_cmd(
    name: str = typer.Argument(..., help="Device name, from `devices list`."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
) -> None:
    """Permanently remove one of your own devices and everything it was
    connected to. Not reversible -- but frees the name for reuse, e.g. if
    the device was wiped and you're re-enrolling it from scratch. To
    temporarily take a device offline instead, use `disable`.

    Examples:

        frp-jump-client devices delete old-laptop

        frp-jump-client devices delete old-laptop --yes
    """
    if not yes and not typer.confirm(f"Delete {name!r} permanently? This cannot be undone."):
        raise typer.Exit(0)
    settings = Settings()
    state = _require_state(settings)
    try:
        poller.delete_device(state, name)
    except poller.SyncError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    stale = [p for p, profile in state.profiles.items() if profile.device_name == name]
    for profile_name in stale:
        del state.profiles[profile_name]
    if stale:
        save(settings.data_dir, state)
    request_wake(settings.data_dir)
    console.print(f"[green]Deleted[/green] {name}.")


@devices_app.command("disable")
def devices_disable_cmd(
    name: str = typer.Argument(..., help="Device name, from `devices list`."),
) -> None:
    """Tear down and block one of your own devices' connections, without
    losing its enrollment -- reversible with `enable`. Useful if a device
    is lost or you suspect it's compromised, without committing to
    re-enrolling it later.

    Example:

        frp-jump-client devices disable old-laptop
    """
    settings = Settings()
    state = _require_state(settings)
    try:
        poller.disable_device(state, name)
    except poller.SyncError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    console.print(f"[green]Disabled[/green] {name}.")


@devices_app.command("enable")
def devices_enable_cmd(
    name: str = typer.Argument(..., help="Device name, from `devices list`."),
) -> None:
    """Undo `disable`.

    Example:

        frp-jump-client devices enable old-laptop
    """
    settings = Settings()
    state = _require_state(settings)
    try:
        poller.enable_device(state, name)
    except poller.SyncError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    console.print(f"[green]Enabled[/green] {name}.")


profiles_app = typer.Typer(
    help="Manage saved connection profiles -- local DEVICE:PORT shortcuts "
    "created by `connect`. Purely client-side, never sent to the server."
)
app.add_typer(profiles_app, name="profiles")


@profiles_app.command("list")
def profiles_list_cmd() -> None:
    """List your saved connection profiles.

    Example:

        frp-jump-client profiles list
    """
    settings = Settings()
    state = _require_state(settings)
    table = Table()
    table.add_column("Name")
    table.add_column("Device")
    table.add_column("Port")
    for profile_name, profile in sorted(state.profiles.items()):
        table.add_row(profile_name, profile.device_name, str(profile.target_port))
    console.print(table)


@profiles_app.command("delete")
def profiles_delete_cmd(
    name: str = typer.Argument(..., help="Profile name, from `profiles list`."),
) -> None:
    """Remove a saved profile. Doesn't tear down anything server-side --
    run `disconnect` first if the connection is still up. To edit a
    profile instead, delete it and `connect DEVICE:PORT --as <name>` again.

    Example:

        frp-jump-client profiles delete wb01-web
    """
    settings = Settings()
    state = _require_state(settings)
    if name not in state.profiles:
        console.print(
            f"[red]no such profile[/red] {name!r} -- see [bold]frp-jump-client profiles list[/bold]"
        )
        raise typer.Exit(1)
    del state.profiles[name]
    save(settings.data_dir, state)
    console.print(f"[green]Deleted profile[/green] {name}.")
