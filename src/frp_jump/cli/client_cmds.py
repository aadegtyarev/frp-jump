"""`frp-jump client ...` -- enroll this device, run its tunnel agent, and
self-serve device/connection management (no server-side admin action
needed for any of it once you have one enrolled device)."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from frp_jump.agent import enroll as enroll_mod
from frp_jump.agent import poller
from frp_jump.agent.state import Profile, load, save
from frp_jump.common.settings import Settings
from frp_jump.driver.base import ServiceProtocol
from frp_jump.driver.frp.binaries import ensure_installed
from frp_jump.driver.frp.driver import FrpDriver

app = typer.Typer(
    help="Enroll this device, run its tunnel agent, and manage your own devices/connections."
)
console = Console()

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
            "[bold]frp-jump-client enroll <url> <token>[/bold] first"
        )
        raise typer.Exit(1)
    return state


def _make_driver(settings: Settings) -> FrpDriver:
    binaries = ensure_installed(settings.data_dir / "bin", version=settings.frp_version)
    return FrpDriver(
        binary=binaries.frpc,
        state_dir=settings.data_dir / "frpc",
        admin_port=settings.frpc_admin_port,
        fallback_timeout_ms=settings.xtcp_fallback_timeout_ms,
    )


@app.command("enroll")
def enroll_cmd(
    control_url: str = typer.Argument(
        ..., help="Base URL of the frp-jump server, e.g. https://tunnel.example.com"
    ),
    token: str = typer.Argument(..., help="One-time enroll token you were given."),
    name: str | None = typer.Option(
        None,
        "--name",
        help="This device's name. Only needed if the token doesn't already fix "
        "one -- the command you were given tells you which.",
    ),
) -> None:
    """Trade a one-time enroll token for this device's identity.

    This is always the first command run on a new device. The token comes
    from an admin's WebUI "Add device" form, or from another of your own
    devices via `add-device`.

    Examples:

        frp-jump-client enroll https://tunnel.example.com abc123...

        frp-jump-client enroll https://tunnel.example.com abc123... --name laptop
    """
    settings = Settings()
    try:
        state = enroll_mod.enroll(
            control_url=control_url, token=token, data_dir=settings.data_dir, requested_name=name
        )
    except enroll_mod.EnrollError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    console.print(
        f"[green]Enrolled[/green] as [bold]{state.device_name}[/bold] ({state.device_id})"
    )
    console.print("Next: [bold]frp-jump-client run[/bold] (or enable the systemd service).")


@app.command("run")
def run_cmd(
    agent_version: str = typer.Option(_AGENT_VERSION, help="Reported to the server on heartbeats."),
) -> None:
    """Run the agent loop in the foreground: heartbeat, pull desired state,
    apply it to the local frpc process and ~/.ssh/config, repeat.

    Meant to be wrapped by systemd (see packaging/systemd/), not run by hand
    day-to-day -- but running it in a terminal is the easiest way to watch
    what it's doing while setting things up.

    Example:

        frp-jump-client run
    """
    settings = Settings()
    state = _require_state(settings)
    driver = _make_driver(settings)

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

    exposed = Table(title="Exposed (other devices can reach these ports on you)")
    exposed.add_column("Port")
    for g in remote["exposed"]:
        exposed.add_row(str(g["target_port"]))
    console.print(exposed)

    profile_by_target = {
        (p.device_name, p.target_port): name for name, p in state.profiles.items()
    }
    consumed = Table(title="Consumed (ports you connected to, via `connect`)")
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


@app.command("add-device")
def add_device_cmd(
    name: str | None = typer.Option(
        None,
        "--name",
        help="Fix the new device's name now. Leave unset to let the new "
        "device pick its own name at enroll time (`enroll ... --name`).",
    ),
) -> None:
    """Mint a one-time enroll token for one more device of your own --
    self-service chaining, no admin action needed once you have one
    enrolled device.

    Examples:

        frp-jump-client add-device

        frp-jump-client add-device --name laptop
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


@app.command("list")
def list_cmd() -> None:
    """List every device you own (yours and any you've added with `add-device`).

    Example:

        frp-jump-client list
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
        status = "[red]revoked[/red]" if d["revoked"] else "active"
        table.add_row(d["name"], status, d["last_seen_at"] or "never")
    console.print(table)


@app.command("delete-device")
def delete_device_cmd(
    name: str = typer.Argument(..., help="Device name, from `frp-jump-client list`."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
) -> None:
    """Permanently remove one of your own devices and everything it was
    connected to. Not reversible -- but frees the name for reuse, e.g. if
    the device was wiped and you're re-enrolling it from scratch.

    Examples:

        frp-jump-client delete-device old-laptop

        frp-jump-client delete-device old-laptop --yes
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
    console.print(f"[green]Deleted[/green] {name}.")


@app.command("connect")
def connect_cmd(
    device: str = typer.Argument(..., help="Device to connect to, from `frp-jump-client list`."),
    port: int = typer.Argument(..., help="Port on that device to connect to, e.g. 22 for SSH."),
    protocol: str = typer.Option(
        "ssh", "--protocol", help="What's listening on that port: ssh, tcp, or http."
    ),
    as_name: str | None = typer.Option(
        None,
        "--as",
        help="Local name for this connection (used by `disconnect` and, for "
        "ssh, as the `ssh <name>` host alias). Defaults to the device's own "
        "name -- pick one explicitly if you connect to more than one port "
        "on the same device.",
    ),
) -> None:
    """Wire this device up to consume a port on another device you own.

    Safe to re-run -- connecting again reuses the existing connection.
    Takes effect within one agent poll interval on both ends, not
    instantly; run `frp-jump-client status` to check.

    Examples:

        frp-jump-client connect wb01 22

        frp-jump-client connect wb01 8080 --protocol http --as wb01-web
    """
    try:
        protocol_enum = ServiceProtocol(protocol)
    except ValueError:
        console.print(f"[red]unknown protocol {protocol!r}[/red] -- use ssh, tcp, or http")
        raise typer.Exit(1) from None

    settings = Settings()
    state = _require_state(settings)
    profile_name = as_name or device

    existing = state.profiles.get(profile_name)
    if existing is not None and (existing.device_name, existing.target_port) != (device, port):
        console.print(
            f"[red]{profile_name!r} is already used[/red] for "
            f"{existing.device_name}:{existing.target_port} -- pick a different --as name"
        )
        raise typer.Exit(1)

    try:
        poller.connect(state, device_name=device, target_port=port, protocol=protocol_enum)
    except poller.SyncError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    state.profiles[profile_name] = Profile(device_name=device, target_port=port)
    save(settings.data_dir, state)
    console.print(
        f"[green]Connected[/green] to {device}:{port} as [bold]{profile_name}[/bold] "
        f"-- takes effect within ~{settings.agent_poll_interval_seconds:.0f}s."
    )


@app.command("disconnect")
def disconnect_cmd(
    profile: str = typer.Argument(
        ..., help="Local name from `connect --as` (or the device name, if you didn't set one)."
    ),
) -> None:
    """Drop a connection previously made with `connect`.

    Example:

        frp-jump-client disconnect wb01
    """
    settings = Settings()
    state = _require_state(settings)
    target = state.profiles.get(profile)
    if target is None:
        console.print(
            f"[red]no such connection[/red] {profile!r} -- see [bold]frp-jump-client status[/bold]"
        )
        raise typer.Exit(1)

    try:
        poller.disconnect(state, device_name=target.device_name, target_port=target.target_port)
    except poller.NotConnectedError:
        # Already gone server-side (e.g. the target device was deleted, or
        # an admin revoked the grant) -- the desired end state is reached
        # either way, so still prune the local profile instead of leaving
        # it stuck forever (it would otherwise block reusing this --as name).
        pass
    except poller.SyncError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    del state.profiles[profile]
    save(settings.data_dir, state)
    console.print(f"[green]Disconnected[/green] {profile}.")
