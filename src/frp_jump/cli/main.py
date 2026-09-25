"""frp-jump CLI entry point."""

from __future__ import annotations

import typer

from frp_jump.cli import client_cmds, server_cmds

app = typer.Typer(
    help="frp-jump: p2p-with-relay-fallback ssh/http/tcp tunnels between Linux boxes, over frp."
)
app.add_typer(server_cmds.app, name="server")
app.add_typer(client_cmds.app, name="client")


if __name__ == "__main__":
    app()
