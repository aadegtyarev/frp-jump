"""`frp-jump client ...` -- enroll this device and run its tunnel agent."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from frp_jump.agent import enroll as enroll_mod
from frp_jump.agent import poller
from frp_jump.agent.state import load
from frp_jump.common.settings import Settings
from frp_jump.driver.frp.binaries import ensure_installed
from frp_jump.driver.frp.driver import FrpDriver

app = typer.Typer(help="Enroll this device and run its tunnel agent.")
console = Console()


def _ssh_config_path(settings: Settings) -> Path:
    return settings.ssh_config_path or (Path.home() / ".ssh" / "config")


def _require_state(settings: Settings):
    state = load(settings.data_dir)
    if state is None:
        console.print(
            "[red]not enrolled[/red] -- run [bold]frp-jump client enroll <url> <token>[/bold] first"
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
    token: str = typer.Argument(..., help="One-time enroll token from the server's WebUI."),
) -> None:
    """Trade a one-time enroll token for this device's identity."""
    settings = Settings()
    try:
        state = enroll_mod.enroll(control_url=control_url, token=token, data_dir=settings.data_dir)
    except enroll_mod.EnrollError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    console.print(
        f"[green]Enrolled[/green] as [bold]{state.device_name}[/bold] ({state.device_id})"
    )
    console.print("Next: [bold]frp-jump client run[/bold] (or enable the systemd service).")


@app.command("run")
def run_cmd(
    agent_version: str = typer.Option("0.1.0", help="Reported to the server on heartbeats."),
) -> None:
    """Run the agent loop in the foreground. Intended to be wrapped by systemd."""
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
        agent_version=agent_version,
    )


@app.command("status")
def status_cmd() -> None:
    """Show this device's identity and what it currently exposes/consumes."""
    settings = Settings()
    state = _require_state(settings)

    console.print(f"Device: [bold]{state.device_name}[/bold] ({state.device_id})")
    console.print(f"Server: {state.control_url}   Relay: {state.relay_addr}:{state.relay_port}")

    try:
        remote = poller.fetch_desired_state(state)
    except poller.SyncError as exc:
        console.print(f"[yellow]could not reach server: {exc}[/yellow]")
        raise typer.Exit(1) from exc

    exposed = Table(title="Exposed")
    exposed.add_column("Service")
    exposed.add_column("Local port")
    for g in remote["exposed"]:
        exposed.add_row(g["service_name"], str(g["target_port"]))
    console.print(exposed)

    consumed = Table(title="Consumed")
    consumed.add_column("Service")
    consumed.add_column("From device")
    consumed.add_column("Protocol")
    consumed.add_column("Local address")
    for g in remote["consumed"]:
        local_port = state.local_ports.get(g["grant_id"])
        addr = f"127.0.0.1:{local_port}" if local_port else "not yet synced"
        consumed.add_row(g["service_name"], g["exposer_device_name"], g["protocol"], addr)
    console.print(consumed)


@app.command("doctor")
def doctor_cmd() -> None:
    """Sanity-check this device: enrolled? frp binary present? server reachable?"""
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
