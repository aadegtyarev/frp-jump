# frp-jump

Connect Linux boxes (including Wiren Board controllers) to each other over
the internet using the SSH/TCP clients you already have — no manual port
juggling, and no caring whether the link ended up peer-to-peer or relayed
through your server.

- **Tunneling** is [frp](https://github.com/fatedier/frp) (frpc/frps),
  driven through an abstract `TunnelDriver`/`RelayDriver` interface — see
  [`docs/architecture.md`](docs/architecture.md).
- **P2P with relay fallback** is frp's own `xtcp` + `fallbackTo` feature: a
  device pair first tries a direct (hole-punched) connection, and
  transparently falls back to relaying through your server if that doesn't
  complete within a timeout.
- **Identity**: a person is identified by an SSH public key (`users
  add-key`), not an email/password account. There is no WebUI — admin
  actions are `frp-jump-server` commands run over SSH to the box.
- **Encryption**: a private CA (run by your server) issues an mTLS cert to
  every enrolled device, so nothing unenrolled can reach the relay at all.
  A per-pair secret gates every connection, and the tunneled traffic
  itself — not just the control channel — is encrypted too.
- **Self-service**: once a person's first device is enrolled, they manage
  everything else themselves from the CLI (adding devices, connecting to
  each other), scoped to devices they own. Disabling a device or deleting a
  grant takes effect on its next sync, not instantly.
- **UX goal**: after setup, `ssh <name>` just works with your stock ssh
  client, whether the path underneath is p2p or relayed.

## Installing the CLI

Two supported ways to install, plus a manual fallback. Either one gets you
the same `frp-jump-client`/`frp-jump-server` CLIs; pick whichever fits how
you manage the box.

### Option A: pip

Published on PyPI as [`frp-jump`](https://pypi.org/project/frp-jump/),
Python 3.12+ required. It splits into two lean pieces sharing one package,
so a device install doesn't pull in the server's dependencies:

```sh
python3 -m venv .venv    # Debian/Ubuntu: `apt install python3-venv` first

# on the server box:
.venv/bin/pip install 'frp-jump[server]'   # pulls in fastapi/uvicorn/sqlmodel
.venv/bin/frp-jump-server ...

# on every device you want to connect (including headless/IoT ones):
.venv/bin/pip install frp-jump             # lean: no server-only deps
.venv/bin/frp-jump-client ...
```

Both commands are always on `PATH` after either install — `frp-jump-server`
just tells you to `pip install 'frp-jump[server]'` and exits cleanly if you
run it on a device-only install.

Put `.venv/bin` on `PATH`, or call the binaries by their full path.

### Option B: apt repository (Debian/Ubuntu, including Wiren Board)

A self-contained `.deb` (own Python 3.12 runtime, no venv/pip involved) via
a signed apt repo hosted on GitHub Pages — add it once, then `apt upgrade`
picks up new releases like any other package:

```sh
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://aadegtyarev.github.io/frp-jump/frp-jump-archive-keyring.asc \
  | sudo gpg --dearmor -o /etc/apt/keyrings/frp-jump.gpg
echo "deb [signed-by=/etc/apt/keyrings/frp-jump.gpg] https://aadegtyarev.github.io/frp-jump stable main" \
  | sudo tee /etc/apt/sources.list.d/frp-jump.list

sudo apt update
sudo apt install frp-jump-client
```

Only `frp-jump-client` is packaged as a `.deb` today — run the server side
via pip.

### Fallback: download a `.deb` directly

Each [GitHub Release](https://github.com/aadegtyarev/frp-jump/releases)
also attaches the `.deb` for each architecture (amd64/arm64/armhf)
individually — useful for an air-gapped box, or if you'd rather not add the
apt repo. You're then on your own for upgrades (repeat the download each
release):

```sh
wget https://github.com/aadegtyarev/frp-jump/releases/download/vX.Y.Z/frp-jump-client_X.Y.Z_arm64.deb
sudo apt install ./frp-jump-client_X.Y.Z_arm64.deb
```

Every command has full `--help` text with runnable examples — start there
if anything below is unclear (`frp-jump-client <command> --help`). Both
`frp-jump-client`/`frp-jump-server` also support `--version`.

## Quick start

On the **server** (a box with a public IP/domain):

```sh
sudo frp-jump-server install-service --relay-public-addr tunnel.example.com \
  --tls-cert /etc/letsencrypt/live/tunnel.example.com/fullchain.pem \
  --tls-key /etc/letsencrypt/live/tunnel.example.com/privkey.pem
```

That one command creates a dedicated, unprivileged `frp-jump` system user,
bootstraps the CA/database under its own `/var/lib/frp-jump`, and installs
+ starts a hardened systemd unit serving real HTTPS directly — see
"systemd" below. `server run` refuses to serve the control-plane API in
cleartext on a public address (it carries mTLS certs and bearer tokens on
every call) — no `--tls-cert`/`--tls-key`? Drop them and it binds
`127.0.0.1` only, and you put your own TLS-terminating reverse proxy (a
couple of lines of nginx/Caddy config) in front of it instead — either
way works, pick whichever you already have. To do it by hand instead:

```sh
export FRP_JUMP_RELAY_PUBLIC_ADDR=tunnel.example.com   # or a bare IP
frp-jump-server init
frp-jump-server run          # foreground; wrap with systemd for real use
```

In another shell (or over SSH, any time later), register yourself:

```sh
frp-jump-server users add-key ~/.ssh/id_ed25519.pub --label me
```

Now enroll your first device — key-based needs no token, once your key is
registered; token-based works for a device you don't want to hand a
personal key to:

```sh
frp-jump-client enroll https://tunnel.example.com ~/.ssh/id_ed25519 --name laptop

# or, token-based:
frp-jump-server enroll-tokens create --user me --name wb01
frp-jump-client enroll https://tunnel.example.com <token-from-above>
```

Run as root, `enroll` also installs and starts the systemd service right
away; otherwise it tells you to run one of these next:

```sh
frp-jump-client install-service          # isolated system account, created for you (needs root)
frp-jump-client install-service --user   # your own account instead, no root needed
```

From there, everything is self-service — no more admin action needed for
that person, ever, even to add a tenth device or reconfigure who talks to
whom:

```sh
frp-jump-client devices add-token               # mint a token to chain-enroll
                                                 # another of your own devices
frp-jump-client devices list                    # devices you own
frp-jump-client connect wb01:22                 # tunnel to port 22 on "wb01"
                                                 # (22/2222 are well-known ssh
                                                 # ports; anything else is a
                                                 # plain tcp tunnel, or --ssh)
frp-jump-client status                          # what's exposed/consumed,
                                                 # local addresses, and whether
                                                 # each exposed port is
                                                 # actually being listened on
frp-jump-client doctor                          # something seems wrong? run
                                                 # this first
frp-jump-client disconnect wb01                 # tear it back down
frp-jump-client devices disable old-laptop      # lost it? block its connections
frp-jump-client devices delete old-laptop       # gone for good, frees the name
```

Once synced (each side's agent polls every `agent_poll_interval_seconds`,
default 2s — override per-run with `frp-jump-client run --poll-interval N`):

```sh
ssh wb01                     # just works -- `connect`'s local profile name
                              # doubles as the ssh_config Host alias
```

An admin can see everyone's devices and connections (including a compact
relayed-traffic figure) without touching anyone's box:

```sh
frp-jump-server users list
frp-jump-server users show me
frp-jump-server devices list
frp-jump-server devices disable wb01 --user me    # force-disconnect + block,
                                                   # reversible with `enable`
```

## Configuration

Everything configurable lives in one place:
[`src/frp_jump/common/settings.py`](src/frp_jump/common/settings.py) — set
via `FRP_JUMP_<FIELD>` environment variables, or a TOML file
(`$FRP_JUMP_CONFIG_FILE`, else the first of `./frp-jump.toml`,
`~/.config/frp-jump/config.toml`, `/etc/frp-jump/config.toml` that exists).
Env vars win over the file.

The only setting with no sane default is `relay_public_addr` — the address
other devices dial to reach your relay; `frp-jump-server init`/`run` refuse
to start without it.

## Ports and firewalls

**On the server**, open these inbound:

| Port | Setting | What it's for |
| --- | --- | --- |
| 7000/tcp | `relay_bind_port` | frps control channel, dialed by every enrolled device's frpc |
| 8443/tcp | `api_port` | The agent-facing HTTPS API — **only** if you gave `install-service` `--tls-cert`/`--tls-key` (direct TLS). Using a reverse proxy instead? Open *its* port (typically 443), not this one — `api_host` stays `127.0.0.1` and never needs a firewall rule. |

`frps_admin_port` (7500) is bound to `127.0.0.1` only and never needs a
firewall rule either way. `server run` refuses to bind `api_host` to
anything but `127.0.0.1` without TLS configured, so there's no way to
end up accidentally serving the API in cleartext to the internet --
`FRP_JUMP_ALLOW_INSECURE_BIND=true` is the explicit override, for the
rare case TLS is genuinely terminated elsewhere on a path this process
can't see.

**On every client device**, allow *outbound* to the relay's `relay_bind_port`
and whichever port actually reaches the control-plane API. p2p (`xtcp`)
hole-punching also needs outbound UDP to work —
a firewall that blocks it (or restricts frpc's ephemeral source ports)
won't break anything outright, but every connection will silently fall
back to relay instead of going peer-to-peer, since the relay fallback
only needs the already-open TCP control channel above. The consumer's own
locally-bound port (`agent_local_port_range_*`, default 40000-40999) is
only ever bound to `127.0.0.1`, so it never needs a firewall rule either.

## systemd

**Client** — `frp-jump-client install-service [--user | --system-user
NAME]` generates and
enables the unit for you (see "Quick start" above). By default, a
dedicated, unprivileged `frp-jump-client` system account is created
automatically — least-privilege, zero extra thinking. Which mode to pick:

- A device that *consumes* an SSH grant needs the agent running as the
  actual human (so it can maintain their real `~/.ssh/config`) — use
  `--user`, or point `FRP_JUMP_SSH_CONFIG_PATH` at that person's config
  explicitly.
- A device that only *exposes* services (e.g. a Wiren Board controller),
  or consumes without needing `ssh <name>` to just work, is fine with the
  default.

Already enrolled the traditional way (as yourself, or root on a
no-other-account device)? The default keeps using that instead of
creating a new account, so it never orphans already-enrolled state — and
if the dedicated account genuinely can't reach the installed binary (e.g.
a personal venv under a home directory other accounts can't traverse
into), it falls back to your own account rather than failing. Explicit
`--system-user NAME` remains available if you want a name other than the
default.

Reach for [`packaging/systemd/`](packaging/systemd/) directly only for a
manual or packaged (`.deb`) install.

**Logging**: a healthy agent is quiet in `journalctl`. frpc's own
internal log level is turned down to `warn` (genuine problems still show
up); the agent logs its own meaningful lifecycle events -- what's
currently exposed/consumed -- at `INFO`, once per change, not every poll
cycle. Nothing here is `DEBUG` by default. Same for the server: uvicorn's
per-request access log is off (every enrolled device's heartbeat/
desired-state poll would otherwise log a line every
`agent_poll_interval_seconds`), errors still surface normally.

**Server** — `frp-jump-server install-service [--system-user NAME]
[--relay-public-addr ADDR]` is the equivalent one-shot setup: creates the
system account, bootstraps the CA/database, writes
`/etc/frp-jump/<name>.env`, and installs a hardened unit
(`ProtectSystem=strict`, `NoNewPrivileges=yes`, one writable data
directory) — matching
[`packaging/systemd/frp-jump-server.service`](packaging/systemd/frp-jump-server.service)
if you'd rather set it up by hand.

## Development

```sh
uv sync
uv run pytest tests/unit -q        # fast, no network
uv run ruff check .
uv run pytest tests/integration -m integration -q   # downloads real frp binaries; loopback only
```

The integration test proves the whole chain works over loopback (real frp
binaries, real mTLS, real xtcp-timeout-then-stcp-fallback), but it can't
prove real NAT hole-punching across two separate networks — check that
manually on real devices.

## Layout

```
src/frp_jump/
  common/     PKI (private CA), opaque tokens, settings, DB models
  driver/     TunnelDriver/RelayDriver abstraction; driver/frp/ = the frp
              implementation (config rendering, binary download+checksum,
              process supervision)
  server/     control-plane: registry (CRUD), the agent-facing API,
              bootstrap (`server init`) -- no WebUI, admin is CLI-only
  agent/      runs on every device: enroll (token or SSH key), the sync
              loop, local profiles, ssh_config management, systemd
              install (`agent/service_install.py`)
  cli/        `frp-jump-server ...` / `frp-jump-client ...`
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Changes are tracked in
[`CHANGELOG.md`](CHANGELOG.md).

## License

[MIT](LICENSE)
