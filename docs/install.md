# Installation

There are two commands in this project, and both come from the same package:

- `frp-jump-client` — runs on every machine you want to connect.
- `frp-jump-server` — runs on the one machine with a public address.

Pick an installation method per machine. They interoperate; your server can use
pip while your devices use apt.

| Method | Good for | Gives you |
| --- | --- | --- |
| [apt repository](#apt-repository) | Debian, Ubuntu, Wiren Board | `frp-jump-client`, upgraded by `apt upgrade` |
| [pip](#pip) | The server, or any box with Python 3.12+ | both commands |
| [a `.deb` file](#a-single-deb-file) | Air-gapped boxes | `frp-jump-client`, upgraded by hand |

## apt repository

The `.deb` ships its own Python 3.12 runtime, so nothing on the machine needs to
have Python at all. Add the repository once:

```sh
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://aadegtyarev.github.io/frp-jump/frp-jump-archive-keyring.asc \
  | sudo gpg --dearmor -o /etc/apt/keyrings/frp-jump.gpg

echo "deb [signed-by=/etc/apt/keyrings/frp-jump.gpg] https://aadegtyarev.github.io/frp-jump stable main" \
  | sudo tee /etc/apt/sources.list.d/frp-jump.list

sudo apt update
sudo apt install frp-jump-client
```

New releases then arrive with your normal `apt upgrade`.

Only the client is packaged this way. Install the server side with pip.

## pip

Python 3.12 or newer. The package is [`frp-jump`](https://pypi.org/project/frp-jump/)
on PyPI, and it splits in two so a device install doesn't drag in the server's
dependencies.

On a device:

```sh
python3 -m venv .venv            # on Debian/Ubuntu: apt install python3-venv first
.venv/bin/pip install frp-jump
.venv/bin/frp-jump-client --version
```

On the server:

```sh
python3 -m venv .venv
.venv/bin/pip install 'frp-jump[server]'   # adds fastapi, uvicorn, sqlmodel, cryptography
.venv/bin/frp-jump-server --version
```

Both commands land on `PATH` either way. If you run `frp-jump-server` from a
device-only install, it tells you to install the `[server]` extra and exits
cleanly instead of failing with an import error.

Add `.venv/bin` to your `PATH`, or call the commands by their full path. If you
plan to run `sudo frp-jump-client install-service`, note that `sudo` resets
`PATH` — the command prints the absolute path to use.

## A single `.deb` file

Every [GitHub release](https://github.com/aadegtyarev/frp-jump/releases)
attaches a `.deb` per architecture (amd64, arm64, armhf). Useful when the
machine can't reach GitHub Pages, or you'd rather not add a repository.

```sh
wget https://github.com/aadegtyarev/frp-jump/releases/download/vX.Y.Z/frp-jump-client_X.Y.Z_arm64.deb
sudo apt install ./frp-jump-client_X.Y.Z_arm64.deb
```

Upgrades are on you: repeat the download for each release.

## What gets downloaded later

No installation method bundles frp itself. The first time an agent runs, it
downloads the pinned frp release for its architecture, verifies the checksum,
and keeps the binaries under its data directory. That means the first
`frp-jump-client run` needs outbound internet access, and later ones don't.

The version is pinned in configuration (`frp_version`), so every machine in one
deployment speaks the same frp.

## Next

- [Getting started](getting-started.md) — set up the server and your first two
  devices.
