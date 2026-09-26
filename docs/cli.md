# CLI reference

Two commands, both installed by the same package.

- `frp-jump-client` — on every machine. Enroll it, run its agent, manage your
  own devices and connections.
- `frp-jump-server` — on the server only. Register people, see everything,
  intervene when needed.

Both accept `--version`. Every subcommand has `--help` with runnable examples,
which is more detailed than the summaries here.

---

# frp-jump-client

## Overview

| Command | Does |
| --- | --- |
| [`enroll`](#enroll) | Trade a token or your SSH key for this device's identity |
| [`install-service`](#install-service) | Install and start the systemd unit |
| [`run`](#run) | Run the agent in the foreground |
| [`status`](#status) | What this device exposes and consumes |
| [`doctor`](#doctor) | Check the basics when something is wrong |
| [`connect`](#connect) | Use a port on another of your devices |
| [`disconnect`](#disconnect) | Tear that back down |
| [`devices`](#devices) | Add, list, delete, disable your own devices |
| [`profiles`](#profiles) | Manage local connection shortcuts |
| [`set-key`](#set-key) | Rotate your own SSH key |
| [`set-p2p`](#set-p2p) | Turn peer-to-peer off for this device |

## enroll

```
frp-jump-client enroll URL TOKEN_OR_KEYFILE [--name NAME]
                       [--user | --system-user NAME]
```

The first command run on any new device. `TOKEN_OR_KEYFILE` is either a one-time
token, or the path to the **private** key whose public half an admin registered.
Key-based enrollment requires `--name`; a token may already carry one.

Run as root, this installs and starts the service too. Run unprivileged, it
tells you what to run next.

| Flag | Effect |
| --- | --- |
| `--name` | This device's name. Unique among your own devices, not globally |
| `--user` | Install the unit under your own account rather than an isolated one |
| `--system-user NAME` | Use a dedicated system account with this name. Requires root |

```sh
frp-jump-client enroll https://tunnel.example.com ~/.ssh/id_ed25519 --name laptop
sudo frp-jump-client enroll https://tunnel.example.com 4f9c2e... --name wb01
```

## install-service

```
frp-jump-client install-service [--user | --system-user NAME]
```

Writes the systemd unit, enables it, starts it. Idempotent: rerun it after
upgrading the binary to refresh the unit's `ExecStart` path.

With no flags, and run as root, it picks the account for you: an existing
enrollment's account if there is one, otherwise a fresh unprivileged
`frp-jump-client` system account. See
[Configuration](configuration.md#which-account-should-the-agent-run-as) for how
to choose.

## run

```
frp-jump-client run [--poll-interval SECONDS]
```

The agent loop, in the foreground: heartbeat, fetch desired state, reconfigure
frpc, refresh `~/.ssh/config`, sleep, repeat. `install-service` wraps this. Run it by hand only when you want to watch what
it does.

`--poll-interval` overrides `agent_poll_interval_seconds` for this run.

## status

```
frp-jump-client status
```

This device's identity, then two tables: ports it **exposes** to others (with
whether anything is actually listening on them locally), and ports it
**consumes** from others (with the local address you connect to).

## doctor

```
frp-jump-client doctor
```

Four checks, in order: enrolled, frpc binary present, server reachable, protocol
versions compatible. Run this first when something is wrong. Exits non-zero if
anything failed.

## connect

```
frp-jump-client connect DEVICE:PORT [--as NAME] [--ssh] [--local-port N]
frp-jump-client connect PROFILE
```

Wires this device up to consume a port on another device you own, and binds it
on `127.0.0.1` here. Safe to re-run.

Ports 22 and 2222 are treated as SSH, which means an `~/.ssh/config` entry gets
written and `ssh <name>` works. Everything else is a plain TCP tunnel, which
carries whatever is on the port — a web UI, MQTT, a database.

| Flag | Effect |
| --- | --- |
| `--as NAME` | Name this connection. Doubles as the ssh alias. Defaults to the device name, or `device-port` if that is taken |
| `--ssh` | Force SSH handling for a port that isn't 22 or 2222 |
| `--local-port N` | Pin the local port instead of picking a free one |

The local port is bound on loopback only. It is never reachable from your LAN.

```sh
frp-jump-client connect wb01:22                    # ssh wb01
frp-jump-client connect wb01:1883 --as wb01-mqtt   # tcp, on a local port
frp-jump-client connect wb01-mqtt                  # reconnect by profile name
```

## disconnect

```
frp-jump-client disconnect PROFILE|DEVICE:PORT [--from DEVICE] [--yes]
```

Removes the connection server-side. Both agents tear down their tunnels on their
next poll.

`--from` disconnects on behalf of a *different* device of yours — useful for
cleaning up a connection you left running on a machine you are not at.

## devices

```
frp-jump-client devices add-token [--name NAME]
frp-jump-client devices list
frp-jump-client devices delete NAME [--yes]
frp-jump-client devices disable NAME
frp-jump-client devices enable NAME
```

Everything here is scoped to devices you own. A device you don't own returns
"not found", whoever owns it.

`add-token` mints a one-time token for one more device of your own. It is
printed once and expires in 24 hours by default.

`disable` is reversible and takes effect on the target's next poll: its tunnels
go away, and its token stops working for anything that changes state. `delete`
is permanent, and frees the name for reuse.

## profiles

```
frp-jump-client profiles list
frp-jump-client profiles delete NAME
```

A profile is this device's own memory of "what did I call that connection". It
is pure local state — the server never sees it. Deleting one does not tear down
the connection; run `disconnect` for that.

## set-key

```
frp-jump-client set-key NEW_PRIVATE_KEY CURRENT_PRIVATE_KEY
```

Rotates the SSH key that identifies you. Both keys are needed: you sign a
server-issued challenge with each. That way a stolen token from one device
cannot take over your account.

Lost the current key entirely? An admin runs `frp-jump-server users set-key`
instead.

## set-p2p

```
frp-jump-client set-p2p enabled|disabled
```

`disabled` sends every connection *this device consumes* straight to the relay,
skipping hole-punching. Worth doing when peer-to-peer can never work here —
a restrictive NAT, or a VPN capturing all traffic — because otherwise every new
connection waits out the hole-punch timeout first for nothing.

Other devices can still reach *this* one peer-to-peer. The setting only affects
what this device dials out to.

---

# frp-jump-server

Run over SSH to the server box. After `install-service`, a wrapper at
`/usr/local/bin/frp-jump-server` re-runs admin commands as the service account,
so `sudo` access to the box is all you need.

## Overview

| Command | Does |
| --- | --- |
| [`install-service`](#install-service-1) | One-shot setup: account, CA, database, systemd unit |
| [`init`](#init) | Bootstrap the CA and database by hand |
| [`run`](#run-1) | Run the relay and the API in the foreground |
| [`users`](#users) | Register people and rotate their keys |
| [`devices`](#devices-1) | See and intervene on anyone's devices |
| [`enroll-tokens`](#enroll-tokens) | Issue tokens for someone else's first device |

## install-service

```
frp-jump-server install-service [--relay-public-addr ADDR]
                                [--tls-cert FILE --tls-key FILE]
                                [--system-user NAME]
```

Creates the system account, bootstraps the CA and database, writes
`/etc/frp-jump/<system-user>.env`, and installs a hardened unit. Requires root,
and is safe to rerun.

`--relay-public-addr` is required the first time. It is the address devices dial
to reach your relay.

Give `--tls-cert`/`--tls-key` to serve HTTPS directly. Leave them out to bind
`127.0.0.1` and put your own reverse proxy in front.

## init

```
frp-jump-server init
```

Creates the CA and database without touching systemd. For a hand-rolled
deployment. Needs `relay_public_addr` configured first.

## run

```
frp-jump-server run
```

Starts the relay (frps) and the control-plane API in the foreground. Refuses to
start if `api_host` is public and no TLS is configured.

## users

```
frp-jump-server users add-key PUBKEY_FILE [--label NAME]
frp-jump-server users set-key LABEL PUBKEY_FILE
frp-jump-server users list
frp-jump-server users show LABEL
frp-jump-server users delete LABEL [--yes]
```

`add-key` registers a person by their SSH public key. That is the one admin
action a new person needs; every device after their first is self-service.

`set-key` is the recovery path for someone who lost their key. `show` lists that
person's devices and connections, including a compact relayed-traffic figure.

`delete` removes the person and every device they own. Not reversible.

## devices

```
frp-jump-server devices list [--user LABEL]
frp-jump-server devices delete NAME --user LABEL [--yes]
frp-jump-server devices disable NAME --user LABEL
frp-jump-server devices enable NAME --user LABEL
```

The same operations users have, but across everyone. `--user` is mandatory on
the mutating ones, because device names are unique per owner — two people can
both have a `laptop`.

## enroll-tokens

```
frp-jump-server enroll-tokens create --user LABEL [--name NAME]
frp-jump-server enroll-tokens list
frp-jump-server enroll-tokens revoke TOKEN_ID
```

For a person who has no SSH key registered, or a device you would rather not
hand a personal key to. `list` shows unredeemed, unexpired tokens. `revoke`
kills one that went to the wrong place.

---

## See also

- [Configuration](configuration.md) — every setting these commands read.
- [Troubleshooting](troubleshooting.md) — when a command doesn't do what you
  expected.
