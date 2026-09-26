# Configuration

Every knob in frp-jump lives in one file:
[`src/frp_jump/common/settings.py`](../src/frp_jump/common/settings.py). Nothing
else hardcodes a port, a path, or a timeout.

## Where settings come from

Three sources, highest priority first:

1. Environment variables, prefixed `FRP_JUMP_` — `FRP_JUMP_API_PORT=9443`.
2. A TOML file.
3. The built-in defaults.

The TOML file is `$FRP_JUMP_CONFIG_FILE` if set, otherwise the first of these
that exists:

```
./frp-jump.toml
~/.config/frp-jump/config.toml
/etc/frp-jump/config.toml
```

```toml
# /etc/frp-jump/config.toml
relay_public_addr = "tunnel.example.com"
relay_bind_port = 7000
agent_poll_interval_seconds = 5.0
```

`frp-jump-server install-service` writes environment variables to
`/etc/frp-jump/<system-user>.env`, which the unit reads. Edit that file and
`systemctl restart frp-jump-server` to change the server's configuration.

## Settings

The only setting with no usable default is `relay_public_addr`. Both
`frp-jump-server init` and `run` refuse to start without it.

### Server

| Setting | Default | What it does |
| --- | --- | --- |
| `relay_public_addr` | *none* | The address devices dial to reach your relay. A domain or a bare IP |
| `relay_bind_port` | `7000` | The relay's own listening port. Must be reachable from the internet |
| `frps_admin_port` | `7500` | The relay's local admin API. Loopback only |
| `api_host` | `0.0.0.0` | Where the control-plane API listens |
| `api_port` | `8443` | The control-plane API's port |
| `tls_cert_file` | *none* | Full-chain certificate, to serve HTTPS directly |
| `tls_key_file` | *none* | The matching private key |
| `allow_insecure_bind` | `false` | Permit a public `api_host` with no TLS. See below |
| `public_base_url` | *none* | Used only to print copy-pasteable enroll commands |
| `enroll_token_ttl_hours` | `24` | How long a one-time enroll token stays redeemable |
| `enroll_challenge_ttl_seconds` | `120` | How long a key-based enroll nonce stays redeemable |

### Devices

| Setting | Default | What it does |
| --- | --- | --- |
| `data_dir` | `~/.local/share/frp-jump` | State, certificate, frp binaries |
| `agent_poll_interval_seconds` | `2.0` | How often the agent asks the server what to do |
| `agent_local_port_range_start` | `40000` | Bottom of the range consumed connections bind in |
| `agent_local_port_range_end` | `40999` | Top of that range |
| `ssh_config_path` | `~/.ssh/config` | Which ssh config to maintain |
| `device_online_threshold_seconds` | `30.0` | How recent a heartbeat must be to show as "online" |

### Both sides

| Setting | Default | What it does |
| --- | --- | --- |
| `frp_version` | `0.70.0` | Which upstream frp release to download |
| `xtcp_fallback_timeout_ms` | `500` | How long to attempt a direct connection before relaying |

A note on the last one. A successful hole-punch resolves well inside 500 ms, so
raising this mostly just makes *failing* punches slower. If peer-to-peer never
works on a given device, `frp-jump-client set-p2p disabled` skips the attempt
entirely, which is better than a longer timeout.

Raising `agent_poll_interval_seconds` past 30 seconds means raising
`device_online_threshold_seconds` too, or the device will show as offline
between its own heartbeats.

## Ports and firewalls

### On the server, inbound

| Port | Setting | Needed when |
| --- | --- | --- |
| 7000/tcp | `relay_bind_port` | Always. Every enrolled device's frpc dials this |
| 8443/tcp | `api_port` | Only if you serve HTTPS directly, with `--tls-cert`/`--tls-key` |
| 443/tcp | — | Instead of 8443, if a reverse proxy terminates TLS |

`frps_admin_port` (7500) binds `127.0.0.1` and never needs a rule.

### On each device, outbound

- TCP to `relay_bind_port` on the server.
- TCP to whichever port serves the control-plane API.
- **UDP**, for hole-punching. Blocking it doesn't break anything: every
  connection quietly falls back to the relay, because the fallback path only
  needs the TCP control channel that is already open.

Locally bound ports (`40000-40999` by default) are on `127.0.0.1` only. No rule
needed.

### Why the server refuses to start sometimes

The control-plane API carries client certificates and bearer tokens on every
call. `frp-jump-server run` will not serve that in cleartext on an address the
internet can reach. Three ways out:

1. Set `tls_cert_file` and `tls_key_file`. The API serves real HTTPS itself.
2. Set `api_host = "127.0.0.1"` and put nginx or Caddy in front.
3. Set `allow_insecure_bind = true`, if TLS is genuinely terminated somewhere
   this process cannot see — a cloud load balancer on a private network, say.

Option 3 is an explicit opt-out, not a shortcut.

## systemd

### Which account should the agent run as

This is the one real decision on a device, and it comes down to whether the
device needs to write a human's `~/.ssh/config`.

| Situation | Do this | Runs as |
| --- | --- | --- |
| A laptop or workstation where you want `ssh wb01` to work | `enroll` unprivileged, then `sudo install-service` | you |
| A headless device that only exposes ports | `sudo enroll` | a dedicated `frp-jump-client` account |
| You want a specific account name | `sudo install-service --system-user NAME` | that account |
| No root at all | `install-service --user` | you, as a user unit |

`--user` installs a user-level unit, which only runs while that account has a
session — add `loginctl enable-linger $USER` if the machine should keep the
tunnel up with nobody logged in.

The default, with no flags and run as root, is continuity-first: if state
already exists from an earlier unprivileged `enroll`, that account keeps being
used. Picking a "better" account there would orphan a working enrollment.

Alternatively, point `FRP_JUMP_SSH_CONFIG_PATH` at the human's config explicitly
and run under any account you like.

### Unit files

`install-service` generates the units. The checked-in templates under
[`packaging/systemd/`](../packaging/systemd/) are for a manual or packaged
install. The server unit is hardened: `ProtectSystem=strict`,
`NoNewPrivileges=yes`, one writable directory.

### Logging

A healthy agent is quiet.

- frpc's own log level is turned down to `warn`. Real problems still appear.
- The agent logs lifecycle events at `INFO`, once per change, not once per poll.
- On the server, uvicorn's per-request access log is off. Every device polling
  every two seconds would otherwise fill the journal with nothing. Errors still
  surface.

Nothing is at `DEBUG` by default.

```sh
journalctl -u frp-jump-client -f
journalctl -u frp-jump-server -f
```

## See also

- [Troubleshooting](troubleshooting.md)
- [Security model](security.md)
