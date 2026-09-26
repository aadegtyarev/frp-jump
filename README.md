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
  complete within a timeout. Not something this project implements itself.
- **Security**: a private CA (run by your server) issues an mTLS cert to
  every enrolled device, so nothing unenrolled can reach the relay at all;
  a per-pair secret means even enrolled devices can't reach each other's
  services without an explicit grant. There is no WebUI at all — admin
  actions are `frp-jump-server` commands run over SSH to the box, and a
  person is identified by an SSH public key an admin registers once
  (`users add-key`), not an email/password account. After that person's
  first device is enrolled, they self-serve entirely from their own CLI
  (adding more of their own devices, connecting to each other), scoped to
  devices they own. Disabling a device or deleting a grant takes effect on
  its next sync, not instantly — see
  [`docs/architecture.md`](docs/architecture.md) for what that does and
  doesn't cover.
- **UX goal**: after setup, `ssh <name>` just works with your stock ssh
  client, whether the path underneath is p2p or relayed.

## Installing the CLI

Two supported ways to install, plus a manual fallback. Either one gets you
the same `frp-jump-client`/`frp-jump-server` CLIs; pick whichever fits how
you manage the box.

### Option A: pip

Published on PyPI as [`frp-jump`](https://pypi.org/project/frp-jump/),
Python 3.12+ required (already present on any recent Debian/Ubuntu,
including Wiren Board controllers). It splits into two lean pieces sharing
one package, so a device install doesn't pull in the server's dependencies:

```sh
python3 -m venv .venv    # needs the venv module: on Debian/Ubuntu that's
                          # a separate package, `apt install python3-venv`

# on the server box:
.venv/bin/pip install 'frp-jump[server]'   # pulls in fastapi/uvicorn/sqlmodel too
.venv/bin/frp-jump-server ...

# on every device you want to connect (including headless/IoT ones):
.venv/bin/pip install frp-jump             # lean: no server-only deps
.venv/bin/frp-jump-client ...
```

Put `.venv/bin` on `PATH`, or call the binaries by their full path.

### Option B: apt repository (Debian/Ubuntu, including Wiren Board)

A self-contained `.deb` (own Python 3.12 runtime under
`/opt/frp-jump-client`, no venv/pip involved) via a signed apt repo hosted
on GitHub Pages — add it once, then `apt upgrade` picks up new releases
like any other package:

```sh
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://aadegtyarev.github.io/frp-jump/frp-jump-archive-keyring.asc \
  | sudo gpg --dearmor -o /etc/apt/keyrings/frp-jump.gpg
echo "deb [signed-by=/etc/apt/keyrings/frp-jump.gpg] https://aadegtyarev.github.io/frp-jump stable main" \
  | sudo tee /etc/apt/sources.list.d/frp-jump.list

sudo apt update
sudo apt install frp-jump-client   # or frp-jump-server, on the relay box
```

Only `frp-jump-client` is packaged as a `.deb` today (the server side is
meant to run from a venv via pip, per "Quick start" below).

### Fallback: download a `.deb` directly

Each [GitHub Release](https://github.com/aadegtyarev/frp-jump/releases)
also attaches the `.deb` for each architecture (amd64/arm64/armhf)
individually — useful for an air-gapped box, or if you'd rather not add
the apt repo:

```sh
wget https://github.com/aadegtyarev/frp-jump/releases/download/vX.Y.Z/frp-jump-client_X.Y.Z_arm64.deb
sudo apt install ./frp-jump-client_X.Y.Z_arm64.deb
```

You're then on your own for upgrades (repeat the download for each new
version) — Option B does this automatically.

Every command has full `--help` text with runnable examples — start there
if anything below is unclear (`frp-jump-client <command> --help`).

## Quick start

On the **server** (a box with a public IP/domain):

```sh
sudo frp-jump-server install-service --relay-public-addr tunnel.example.com
```

That one command creates a dedicated, unprivileged `frp-jump` system
user, bootstraps the CA/database under its own `/var/lib/frp-jump`, and
installs + starts a hardened systemd unit -- see "systemd" below for
what it actually sets up. Prefer to do it by hand, or already have your
own service-account convention:

```sh
export FRP_JUMP_RELAY_PUBLIC_ADDR=tunnel.example.com   # or a bare IP
frp-jump-server init
frp-jump-server run          # foreground; wrap with systemd for real use
```

In another shell (or over SSH, any time later), register yourself — a
person is identified by an SSH public key, not an account:

```sh
frp-jump-server users add-key ~/.ssh/id_ed25519.pub --label me
```

Now enroll your first device. Two ways, pick whichever's easier for a
given device:

```sh
# key-based -- works for every device once your key is registered, no
# token to hand out. --name is required (there's no hint to fall back on).
frp-jump-client enroll https://tunnel.example.com ~/.ssh/id_ed25519 --name laptop

# token-based -- for a device without your key on it, or one you'd
# rather not hand a personal key to. Mint one first:
frp-jump-server enroll-tokens create --user me --name wb01
frp-jump-client enroll https://tunnel.example.com <token-from-above>
```

Run as root, `enroll` also installs and starts the systemd service right
away; otherwise it tells you to run `install-service` next:

```sh
frp-jump-client install-service                                  # system-wide, needs root
frp-jump-client install-service --user                            # your own account, no root needed
frp-jump-client install-service --system-user frp-jump-client     # isolated account (created for you)
```

From there, everything is self-service — no more admin action needed for
that person, ever, even to add a tenth device or reconfigure who talks to
whom:

```sh
frp-jump-client devices add-token               # mint a token to chain-enroll
                                                 # one more of your own devices
                                                 # (or just enroll it by key)
frp-jump-client devices list                    # devices you own
frp-jump-client connect wb01:22                 # wire yourself up to port 22
                                                 # on your device "wb01" (ssh,
                                                 # 22/2222 are well-known;
                                                 # anything else is a plain
                                                 # tcp tunnel, or pass --ssh)
frp-jump-client status                          # see what's exposed/consumed,
                                                 # and local addresses once synced
frp-jump-client disconnect wb01                 # tear it back down
frp-jump-client devices disable old-laptop      # lost it? block its connections
                                                 # without losing the enrollment
frp-jump-client devices delete old-laptop       # gone for good, frees the name
```

Once synced (each side's agent polls every `agent_poll_interval_seconds`,
default 30s):

```sh
ssh wb01                     # just works -- `connect`'s local profile name
                              # doubles as the ssh_config Host alias
```

An admin can see everyone's devices and connections (including a compact
relayed-traffic figure, when a connection actually went through the
relay) without touching anyone's box:

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
`~/.config/frp-jump/config.toml`, `/etc/frp-jump/config.toml` that
exists). Env vars win over the file. Nothing else in the codebase
hardcodes a port, TTL, or version pin.

The only setting with no sane default is `relay_public_addr` — the
address other devices dial to reach your relay; `frp-jump-server
init`/`run` refuse to start without it.

## systemd

On the client, `frp-jump-client install-service [--user | --system-user
NAME]` generates and enables the unit for you (see "Quick start" above)
— reach for [`packaging/systemd/`](packaging/systemd/) directly only for
a manual or packaged (`.deb`) install. Its comments explain a real
gotcha: a device that *consumes* an SSH grant needs the agent running as
the actual human (so it can maintain their real `~/.ssh/config`) — a
`--user` unit, not a system one, unless you point
`FRP_JUMP_SSH_CONFIG_PATH` at that user's config explicitly. A device
that only *exposes* services (e.g. a Wiren Board controller), or
consumes without needing `ssh <name>` to just work, is fine as a system
service or under `--system-user` — an isolated account created for you,
least-privilege, with its own `/var/lib/<name>`.

On the server, `frp-jump-server install-service [--system-user NAME]
[--relay-public-addr ADDR]` is the equivalent one-shot setup (see "Quick
start" above): creates the system account, bootstraps the CA/database,
writes `/etc/frp-jump/<name>.env`, and installs a hardened unit
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
prove real NAT hole-punching across two separate networks — that's the one
thing to manually check on your own machines after this lands.

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
