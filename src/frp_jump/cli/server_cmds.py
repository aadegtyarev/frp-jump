"""`frp-jump server ...` -- bootstrap and run the control-plane + relay."""

from __future__ import annotations

import datetime

import typer
import uvicorn
from rich.console import Console

from frp_jump.common.settings import Settings
from frp_jump.driver.base import RelayState
from frp_jump.driver.frp.binaries import ensure_installed
from frp_jump.driver.frp.driver import FrpsRelayDriver
from frp_jump.server import auth, bootstrap
from frp_jump.server.app import create_app
from frp_jump.server.db import make_engine, make_session

app = typer.Typer(help="Run and manage the frp-jump server (control-plane + relay).")
console = Console()


@app.command("init")
def init(
    admin_email: str = typer.Option(
        ..., "--admin-email", help="Email identifying the admin account."
    ),
) -> None:
    """Bootstrap this server: private CA, database, and a one-time admin
    login link for the WebUI.

    Run this once, before the first `frp-jump server run`. Configure
    FRP_JUMP_RELAY_PUBLIC_ADDR (or relay_public_addr in the config file)
    first -- see the README for the full list of required settings.

    Example:

        frp-jump server init --admin-email you@example.com
    """
    settings = Settings()
    try:
        result = bootstrap.initialize(settings, admin_email=admin_email)
    except bootstrap.ConfigError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    console.print(f"[green]Server initialized[/green] in {result.data_dir}")
    console.print(f"Admin login link:\n[bold]{result.admin_login_url}[/bold]")
    console.print(
        "Open it in a browser to sign in. It expires; mint a new one any time with "
        "[bold]frp-jump server login-link <email>[/bold]."
    )


@app.command("login-link")
def login_link(
    email: str = typer.Argument(
        ..., help="Admin email to mint a fresh WebUI login link for.", metavar="EMAIL"
    ),
) -> None:
    """Mint a fresh admin WebUI login link (e.g. after the previous one expired).

    The WebUI is admin-only -- regular users never log in to it at all. To
    onboard a friend's first device, use the WebUI's "Add device" form with
    their email as the owner; every device after that is theirs to add via
    their own CLI (`frp-jump-client add-device`), no further action here.

    Example:

        frp-jump server login-link admin@example.com
    """
    settings = Settings()
    ttl = datetime.timedelta(minutes=settings.login_token_ttl_minutes)
    engine = make_engine(bootstrap.db_path(settings))
    with make_session(engine) as db:
        token = auth.issue_login_token(db, email=email, created_by=None, ttl=ttl)
    console.print(bootstrap.build_url(settings, f"/auth/{token}"))


@app.command("run")
def run() -> None:
    """Run the relay (frps) and the control-plane API/WebUI.

    Foreground; meant to be wrapped by systemd (see packaging/systemd/).
    Requires `frp-jump server init` to have run at least once.

    Example:

        frp-jump server run
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

    ssl_kwargs = {}
    if settings.tls_cert_file and settings.tls_key_file:
        ssl_kwargs = {
            "ssl_certfile": str(settings.tls_cert_file),
            "ssl_keyfile": str(settings.tls_key_file),
        }
    else:
        console.print(
            "[yellow]no tls_cert_file/tls_key_file configured -- serving the control-plane "
            "API/WebUI as plain HTTP. Fine behind your own TLS-terminating reverse proxy; "
            "otherwise set FRP_JUMP_TLS_CERT_FILE/FRP_JUMP_TLS_KEY_FILE.[/yellow]"
        )

    try:
        # access_log=False: uvicorn's default access log would write the
        # full request path -- including the raw magic-link token on every
        # `GET /auth/<token>` -- to stdout/journald. These tokens are
        # single-use and short-lived, but an unredeemed one (e.g. a
        # `server login-link` nobody opened yet) would sit valid in the
        # log for its full TTL otherwise.
        uvicorn.run(
            web_app,
            host=settings.webui_host,
            port=settings.webui_port,
            access_log=False,
            **ssl_kwargs,
        )
    finally:
        relay.stop()
