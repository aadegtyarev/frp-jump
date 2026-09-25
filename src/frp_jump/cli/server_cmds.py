"""`frp-jump server ...` -- bootstrap and run the control-plane + relay."""

from __future__ import annotations

import datetime

import typer
import uvicorn
from rich.console import Console

from frp_jump.common.models import TokenPurpose
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
    """Bootstrap this server: private CA, database, and an admin login link."""
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
    email: str = typer.Argument(..., help="Email to mint a fresh login/invite link for."),
    invite: bool = typer.Option(
        False, "--invite", help="Mint a longer-lived invite link instead of a login link."
    ),
) -> None:
    """Mint a fresh magic link (e.g. after the previous one expired)."""
    settings = Settings()
    purpose = TokenPurpose.INVITE if invite else TokenPurpose.LOGIN
    ttl = (
        datetime.timedelta(days=settings.invite_token_ttl_days)
        if invite
        else datetime.timedelta(minutes=settings.login_token_ttl_minutes)
    )
    engine = make_engine(bootstrap.db_path(settings))
    with make_session(engine) as db:
        token = auth.issue_login_token(db, email=email, purpose=purpose, created_by=None, ttl=ttl)
    console.print(bootstrap.build_url(settings, f"/auth/{token}"))


@app.command("run")
def run() -> None:
    """Run the relay (frps) and the control-plane API/WebUI. Foreground; for systemd."""
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
        uvicorn.run(web_app, host=settings.webui_host, port=settings.webui_port, **ssl_kwargs)
    finally:
        relay.stop()
