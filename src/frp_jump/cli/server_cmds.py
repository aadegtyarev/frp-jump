"""`frp-jump-server ...` -- bootstrap and run the control-plane + relay, and
every admin action: registering users by SSH key, and managing devices/
enroll-tokens on their behalf. There is no WebUI -- this CLI, run over SSH
to the server box, is the entire admin surface (see docs/architecture.md)."""

from __future__ import annotations

import datetime
import ipaddress
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from frp_jump.common.settings import Settings
from frp_jump.driver.base import RelayState

# `frp-jump-server`'s own [project.scripts] entry point exists in the same
# base `frp-jump` package/wheel as `frp-jump-client` -- pip always creates
# both console scripts regardless of which extras were requested, since
# entry points aren't gated by extras. Only the imports below actually
# need the `[server]` extra (fastapi/uvicorn/sqlmodel/cryptography); a
# lean client-only `pip install frp-jump` still leaves this command on
# PATH, just non-functional -- so failing here with one clear line beats
# letting a bare `ModuleNotFoundError` traceback (naming some internal
# dependency the user never asked to know about) be the first thing they
# see.
try:
    import uvicorn

    from frp_jump.common.models import User
    from frp_jump.driver.frp.binaries import ensure_installed
    from frp_jump.driver.frp.driver import FrpsRelayDriver, fetch_proxy_traffic
    from frp_jump.server import bootstrap, registry, service_install
    from frp_jump.server.app import create_app
    from frp_jump.server.db import Session, make_engine, make_session
except ModuleNotFoundError as exc:
    print(
        f"frp-jump-server needs extra dependencies that are not installed ({exc.name}).\n"
        "\n"
        "This command runs the control-plane API and relay (frps), which need "
        "fastapi/uvicorn/sqlmodel/cryptography -- kept out of the base package "
        "so a device-only `pip install frp-jump` (e.g. on a Wiren Board "
        "controller) stays lean.\n"
        "\n"
        "Fix: pip install 'frp-jump[server]'",
        file=sys.stderr,
    )
    sys.exit(1)

app = typer.Typer(
    help="Run and manage the frp-jump server (control-plane + relay).", no_args_is_help=True
)
console = Console()

try:
    from importlib.metadata import PackageNotFoundError, version

    _PACKAGE_VERSION = version("frp-jump")
except PackageNotFoundError:
    _PACKAGE_VERSION = "dev"


def _version_callback(value: bool) -> None:
    if value:
        console.print(_PACKAGE_VERSION)
        raise typer.Exit()


@app.callback()
def _main(
    version_: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the installed frp-jump version and exit.",
    ),
) -> None:
    pass


def _open_db(settings: Settings) -> Session:
    return make_session(make_engine(bootstrap.db_path(settings)))


def _is_loopback_host(host: str) -> bool:
    """Whether ``host`` (an ``api_host`` value) never leaves this machine
    on its own -- "localhost" and any ``127.0.0.0/8``/``::1`` literal.
    A hostname that isn't literally "localhost" is treated as NOT
    loopback (even if it happens to resolve there today) -- this gates a
    security check, and a config that only *happens* to be safe by way of
    DNS is exactly the kind of thing worth requiring to be explicit
    instead."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _read_public_key(path: Path) -> str:
    text = path.read_text().strip()
    if not text:
        console.print(f"[red]{path} is empty[/red]")
        raise typer.Exit(1)
    return text


def _require_user(db: Session, label: str) -> User:
    user = registry.get_user_by_label(db, label)
    if user is None:
        console.print(
            f"[red]no such user[/red] {label!r} -- see [bold]frp-jump-server users list[/bold]"
        )
        raise typer.Exit(1)
    return user


def _require_device(db: Session, owner: User, name: str):
    device = registry.get_device_by_name(db, owner.id, name)
    if device is None:
        console.print(f"[red]no such device[/red] {name!r} owned by {owner.label!r}")
        raise typer.Exit(1)
    return device


def _format_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            return f"{value:.0f}{unit}" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}TB"


def _relayed_today(settings: Settings, grant_id: str) -> str | None:
    """`None` when frps has no data at all (not running, or this grant has
    never connected) -- distinct from "0 bytes relayed", which means it
    connected but stayed peer-to-peer. See `driver.frp.driver
    .fetch_proxy_traffic`'s docstring for why this can only ever show
    relayed traffic, never a p2p connection's."""
    traffic = fetch_proxy_traffic(settings.frps_admin_port, grant_id)
    if traffic is None:
        return None
    bytes_in, bytes_out = traffic
    return f"relayed today: {_format_bytes(bytes_in)} in / {_format_bytes(bytes_out)} out"


@app.command("init")
def init() -> None:
    """Bootstrap this server: private CA and database.

    Run this once, before the first `frp-jump-server run`. Configure
    FRP_JUMP_RELAY_PUBLIC_ADDR (or relay_public_addr in the config file)
    first -- see the README for the full list of required settings.

    Example:

        frp-jump-server init
    """
    settings = Settings()
    try:
        result = bootstrap.initialize(settings)
    except bootstrap.ConfigError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    console.print(f"[green]Server initialized[/green] in {result.data_dir}")
    console.print(
        "Next: register yourself as a user -- "
        "[bold]frp-jump-server users add-key ~/.ssh/id_ed25519.pub[/bold]"
    )


@app.command("run")
def run() -> None:
    """Run the relay (frps) and the control-plane API.

    Foreground; meant to be wrapped by systemd (see packaging/systemd/).
    Requires `frp-jump-server init` to have run at least once.

    Example:

        frp-jump-server run
    """
    settings = Settings()
    try:
        ca = bootstrap.load_or_create_ca(settings)
        relay_cert = bootstrap.load_or_create_relay_cert(settings, ca)
    except bootstrap.ConfigError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    binaries = ensure_installed(settings.data_dir / "bin", version=settings.frp_version)
    relay = FrpsRelayDriver(
        binary=binaries.frps,
        state_dir=settings.data_dir / "relay",
        admin_port=settings.frps_admin_port,
    )
    relay.apply(
        RelayState(
            bind_port=settings.relay_bind_port,
            ca_cert_pem=ca.cert_pem,
            cert_pem=relay_cert.cert_pem,
            key_pem=relay_cert.key_pem,
        )
    )
    console.print(f"[green]relay listening[/green] on 0.0.0.0:{settings.relay_bind_port}")

    engine = make_engine(bootstrap.db_path(settings))
    web_app = create_app(settings=settings, engine=engine, ca=ca)

    has_tls = bool(settings.tls_cert_file and settings.tls_key_file)
    ssl_kwargs = {}
    if has_tls:
        ssl_kwargs = {
            "ssl_certfile": str(settings.tls_cert_file),
            "ssl_keyfile": str(settings.tls_key_file),
        }
    elif _is_loopback_host(settings.api_host):
        console.print(
            "[yellow]no tls_cert_file/tls_key_file configured -- serving the control-plane "
            f"API as plain HTTP on {settings.api_host} only. Fine behind your own "
            "TLS-terminating reverse proxy.[/yellow]"
        )
    elif settings.allow_insecure_bind:
        console.print(
            f"[yellow]FRP_JUMP_ALLOW_INSECURE_BIND is set -- serving the control-plane API "
            f"as plain HTTP on {settings.api_host}, not just loopback. Every enroll/heartbeat "
            "call (mTLS certs, bearer tokens) crosses whatever network reaches this host in "
            "cleartext unless something else is genuinely terminating TLS in front of "
            "it.[/yellow]"
        )
    else:
        console.print(
            f"[red]refusing to start: api_host={settings.api_host!r} is reachable from "
            "outside this machine, and no TLS is configured.[/red]\n"
            "Every enroll/heartbeat call carries mTLS certs and bearer tokens -- serving "
            "that in cleartext to the network is not a safe default. Fix one of:\n"
            "  - set FRP_JUMP_TLS_CERT_FILE/FRP_JUMP_TLS_KEY_FILE to a real certificate\n"
            "  - set FRP_JUMP_API_HOST=127.0.0.1 and put your own TLS-terminating reverse "
            "proxy in front (the documented deployment)\n"
            "  - set FRP_JUMP_ALLOW_INSECURE_BIND=true if TLS is genuinely terminated "
            "elsewhere on a path this process can't see"
        )
        raise typer.Exit(1)

    try:
        # Every enrolled device polls every agent_poll_interval_seconds
        # (default 2s) -- uvicorn's default per-request access log would
        # log a heartbeat and a desired-state fetch that often, for every
        # device, forever. Genuine errors (5xx, connection issues) still
        # surface through uvicorn's own error logger, which this doesn't
        # touch.
        uvicorn.run(
            web_app, host=settings.api_host, port=settings.api_port, access_log=False, **ssl_kwargs
        )
    finally:
        relay.stop()


@app.command("install-service")
def install_service(
    system_user: str = typer.Option(
        "frp-jump",
        "--system-user",
        help="Dedicated, unprivileged system account to run as (created if "
        "missing, along with its own /var/lib/<name> data directory).",
    ),
    relay_public_addr: str | None = typer.Option(
        None,
        "--relay-public-addr",
        help="Address other devices will use to reach this server, e.g. "
        "tunnel.example.com. Required the first time; a rerun (e.g. after "
        "upgrading the binary) reuses whatever is already configured.",
    ),
    tls_cert_file: Path | None = typer.Option(
        None,
        "--tls-cert",
        help="Path to a real TLS certificate (full chain) to serve the "
        "control-plane API directly over HTTPS -- e.g. certbot's "
        "fullchain.pem. Must be given together with --tls-key. Without "
        "either, the API binds 127.0.0.1 only and expects your own "
        "TLS-terminating reverse proxy in front (see the README) -- "
        "`server run` refuses to bind a public address with no TLS.",
    ),
    tls_key_file: Path | None = typer.Option(
        None, "--tls-key", help="Path to the private key matching --tls-cert."
    ),
) -> None:
    """One-shot setup: create a dedicated system user, bootstrap the CA/
    database, write config to /etc/frp-jump/<system-user>.env, and
    install + start a hardened systemd unit. Requires root. Safe to
    rerun any time -- it refreshes the unit to point at wherever
    `frp-jump-server` currently is, without touching your existing config.

    This replaces doing all of that by hand -- see docs/architecture.md
    for exactly what it sets up, if you'd rather do it yourself.

    Examples:

        sudo frp-jump-server install-service --relay-public-addr tunnel.example.com

        sudo frp-jump-server install-service --relay-public-addr tunnel.example.com \\
            --tls-cert /etc/letsencrypt/live/tunnel.example.com/fullchain.pem \\
            --tls-key /etc/letsencrypt/live/tunnel.example.com/privkey.pem

        sudo frp-jump-server install-service
    """
    try:
        unit_path = service_install.install(
            system_user=system_user,
            relay_public_addr=relay_public_addr,
            tls_cert_file=tls_cert_file,
            tls_key_file=tls_key_file,
        )
    except service_install.ServiceInstallError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    console.print(f"[green]Installed and started[/green] ({unit_path}).")
    console.print(
        "Next: register yourself as a user -- "
        "[bold]frp-jump-server users add-key ~/.ssh/id_ed25519.pub[/bold]"
    )


# --- users ------------------------------------------------------------

users_app = typer.Typer(
    help="Manage registered users (people identified by an SSH public key).",
    no_args_is_help=True,
)
app.add_typer(users_app, name="users")


@users_app.command("add-key")
def users_add_key(
    pubkey_file: Path = typer.Argument(
        ..., help="Path to their SSH public key, e.g. alice_key.pub."
    ),
    label: str | None = typer.Option(
        None, "--label", help="A friendly name for this user. Auto-generated if omitted."
    ),
) -> None:
    """Register a person by their existing SSH public key. Their first
    device then self-enrolls with it (`frp-jump-client enroll <url>
    <path-to-their-private-key>`) -- no token needed, and every device
    after that is self-service too (`frp-jump-client devices add-token`).

    Examples:

        frp-jump-server users add-key alice_key.pub

        frp-jump-server users add-key alice_key.pub --label alice
    """
    settings = Settings()
    public_key = _read_public_key(pubkey_file)
    with _open_db(settings) as db:
        try:
            user = registry.create_user(db, public_key=public_key, label=label)
        except registry.ConflictError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc
    console.print(f"[green]Registered[/green] {user.label!r} ({user.ssh_key_fingerprint})")


@users_app.command("set-key")
def users_set_key(
    label: str = typer.Argument(..., help="User label, from `users list`."),
    pubkey_file: Path = typer.Argument(..., help="Path to their new SSH public key."),
) -> None:
    """Rotate a user's key -- e.g. they lost the old one. They can also do
    this themselves, without admin involvement, via `frp-jump-client
    set-key`.

    Example:

        frp-jump-server users set-key alice new_key.pub
    """
    settings = Settings()
    public_key = _read_public_key(pubkey_file)
    with _open_db(settings) as db:
        user = _require_user(db, label)
        try:
            registry.set_user_key(db, user.id, public_key=public_key)
        except registry.ConflictError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc
    console.print(f"[green]Updated key[/green] for {label!r}.")


@users_app.command("list")
def users_list() -> None:
    """List every registered user and how many devices they own.

    Example:

        frp-jump-server users list
    """
    settings = Settings()
    with _open_db(settings) as db:
        users = registry.list_users_view(db)
    table = Table()
    table.add_column("Label")
    table.add_column("Fingerprint")
    table.add_column("Devices")
    for u in users:
        table.add_row(u.label, u.fingerprint, str(u.device_count))
    console.print(table)


@users_app.command("show")
def users_show(label: str = typer.Argument(..., help="User label, from `users list`.")) -> None:
    """Show one user's devices and what each is connected to.

    Example:

        frp-jump-server users show alice
    """
    settings = Settings()
    with _open_db(settings) as db:
        user = _require_user(db, label)
        devices = registry.list_devices_for_owner(db, user.id)
        console.print(f"[bold]{label}[/bold] ({user.ssh_key_fingerprint})")
        if not devices:
            console.print("  (no devices)")
        for d in devices:
            status = "enabled" if d.enabled else "[yellow]disabled[/yellow]"
            last_seen = d.last_seen_at.isoformat() if d.last_seen_at else "never"
            console.print(f"  [bold]{d.name}[/bold] -- {status}, last seen {last_seen}")
            for g in registry.exposed_grants_for_device(db, d.id):
                traffic = _relayed_today(settings, g.grant_id)
                suffix = f" -- {traffic}" if traffic else ""
                console.print(f"    exposes :{g.target_port}{suffix}")
            for g in registry.consumed_grants_for_device(db, d.id):
                traffic = _relayed_today(settings, g.grant_id)
                suffix = f" -- {traffic}" if traffic else ""
                console.print(
                    f"    -> {g.exposer_device_name}:{g.target_port} ({g.protocol.value}){suffix}"
                )


@users_app.command("delete")
def users_delete(
    label: str = typer.Argument(..., help="User label, from `users list`."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
) -> None:
    """Permanently remove a user and every device they own. Not reversible.

    Example:

        frp-jump-server users delete alice --yes
    """
    settings = Settings()
    with _open_db(settings) as db:
        user = _require_user(db, label)
        if not yes and not typer.confirm(
            f"Delete {label!r} and all their devices permanently? This cannot be undone."
        ):
            raise typer.Exit(0)
        registry.delete_user(db, user.id)
    console.print(f"[green]Deleted[/green] {label}.")


# --- devices ------------------------------------------------------------

devices_app = typer.Typer(help="Manage devices across all users.", no_args_is_help=True)
app.add_typer(devices_app, name="devices")


@devices_app.command("list")
def devices_list(
    user: str | None = typer.Option(None, "--user", help="Only show devices owned by this user."),
) -> None:
    """List every device, with status and what it's connected to.

    Examples:

        frp-jump-server devices list

        frp-jump-server devices list --user alice
    """
    settings = Settings()
    with _open_db(settings) as db:
        devices = registry.list_devices_view(db)
        if user is not None:
            devices = [d for d in devices if d.owner_label == user]
        table = Table()
        table.add_column("Name")
        table.add_column("Owner")
        table.add_column("Status")
        table.add_column("Last seen")
        table.add_column("Connections")
        for d in devices:
            status = "enabled" if d.enabled else "[yellow]disabled[/yellow]"
            last_seen = d.last_seen_at.isoformat() if d.last_seen_at else "never"
            parts = [
                f"exposes :{g.target_port}"
                for g in registry.exposed_grants_for_device(db, d.id)
            ]
            parts += [
                f"-> {g.exposer_device_name}:{g.target_port}"
                for g in registry.consumed_grants_for_device(db, d.id)
            ]
            table.add_row(d.name, d.owner_label, status, last_seen, ", ".join(parts) or "—")
    console.print(table)


@devices_app.command("delete")
def devices_delete(
    name: str = typer.Argument(..., help="Device name, from `devices list`."),
    user: str = typer.Option(..., "--user", help="The device owner's label."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
) -> None:
    """Permanently remove one device and everything it was connected to.

    `--user` is required -- device names are only unique per-owner, and
    this is a rare, destructive operation worth being precise about.

    Example:

        frp-jump-server devices delete old-laptop --user alice --yes
    """
    settings = Settings()
    with _open_db(settings) as db:
        owner = _require_user(db, user)
        device = _require_device(db, owner, name)
        if not yes and not typer.confirm(f"Delete {name!r} (owned by {user}) permanently?"):
            raise typer.Exit(0)
        registry.delete_device(db, device.id)
    console.print(f"[green]Deleted[/green] {name}.")


@devices_app.command("disable")
def devices_disable(
    name: str = typer.Argument(..., help="Device name, from `devices list`."),
    user: str = typer.Option(..., "--user", help="The device owner's label."),
) -> None:
    """Tear down and block one device's connections, without losing its
    enrollment -- reversible with `devices enable`.

    Example:

        frp-jump-server devices disable wb01 --user alice
    """
    settings = Settings()
    with _open_db(settings) as db:
        owner = _require_user(db, user)
        device = _require_device(db, owner, name)
        registry.disable_device(db, device.id)
    console.print(f"[green]Disabled[/green] {name}.")


@devices_app.command("enable")
def devices_enable(
    name: str = typer.Argument(..., help="Device name, from `devices list`."),
    user: str = typer.Option(..., "--user", help="The device owner's label."),
) -> None:
    """Undo `devices disable`.

    Example:

        frp-jump-server devices enable wb01 --user alice
    """
    settings = Settings()
    with _open_db(settings) as db:
        owner = _require_user(db, user)
        device = _require_device(db, owner, name)
        registry.enable_device(db, device.id)
    console.print(f"[green]Enabled[/green] {name}.")


# --- enroll-tokens --------------------------------------------------------

enroll_tokens_app = typer.Typer(
    help="Issue and manage one-time device enroll tokens.", no_args_is_help=True
)
app.add_typer(enroll_tokens_app, name="enroll-tokens")


@enroll_tokens_app.command("create")
def enroll_tokens_create(
    user: str = typer.Option(..., "--user", help="Who this new device will belong to."),
    name: str | None = typer.Option(
        None, "--name", help="Fix the device's name now; otherwise it picks one at enroll time."
    ),
) -> None:
    """Mint a one-time enroll token for a new device -- for a user without
    an SSH key to register instead (see `users add-key`), or a device
    they'd rather not hand a personal key to (e.g. a shared/disposable
    one).

    Examples:

        frp-jump-server enroll-tokens create --user alice

        frp-jump-server enroll-tokens create --user alice --name wb01
    """
    settings = Settings()
    with _open_db(settings) as db:
        owner = _require_user(db, user)
        try:
            issued = registry.create_enroll_token(
                db,
                created_by=owner.id,
                ttl=datetime.timedelta(hours=settings.enroll_token_ttl_hours),
                device_name_hint=name,
            )
        except (registry.ValidationError, registry.ConflictError) as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc

    server_url = settings.public_base_url or "<server-url>"
    command = f"frp-jump-client enroll {server_url} {issued.token}"
    if not name:
        command += " --name <pick-a-name>"
    console.print("Give this command to the new device (token shown once):")
    console.print(f"[bold]{command}[/bold]")
    console.print(f"Expires: {issued.expires_at.isoformat()}")


@enroll_tokens_app.command("list")
def enroll_tokens_list() -> None:
    """List unredeemed, unexpired enroll tokens.

    Example:

        frp-jump-server enroll-tokens list
    """
    settings = Settings()
    with _open_db(settings) as db:
        pending = registry.list_pending_enroll_tokens(db)
    table = Table()
    table.add_column("ID")
    table.add_column("Owner")
    table.add_column("Name hint")
    table.add_column("Expires")
    for p in pending:
        table.add_row(
            p.id,
            p.owner_label,
            p.device_name_hint or "(picked at enroll)",
            p.expires_at.isoformat(),
        )
    console.print(table)


@enroll_tokens_app.command("revoke")
def enroll_tokens_revoke(
    token_id: str = typer.Argument(..., help="Token id, from `enroll-tokens list`."),
) -> None:
    """Invalidate an unredeemed enroll token before anyone uses it -- e.g.
    it was sent to the wrong person, or leaked.

    Example:

        frp-jump-server enroll-tokens revoke abc123
    """
    settings = Settings()
    with _open_db(settings) as db:
        try:
            registry.revoke_enroll_token(db, token_id)
        except (registry.NotFoundError, registry.ConflictError) as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc
    console.print("[green]Revoked.[/green]")
