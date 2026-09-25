# Architecture

This mirrors the original implementation plan, updated for what actually
got built and a few things learned along the way. See the module layout in
the README first if you haven't already.

## Data flow

```
server/                     control-plane: source of truth
  mini-CA (common/pki.py)   issues device certs on enroll
  SQLite (common/models.py) users, sessions, devices, services, grants,
                             enroll/login tokens
  server/api.py              agent-facing: enroll, heartbeat,
                             desired-state pull (bearer-token auth)
  server/web.py               human-facing WebUI (session-cookie auth via
                             magic link)
  frps managed through the same driver abstraction as frpc

driver/                     abstract TunnelDriver / RelayDriver
  frp/                      concrete implementation: renders frps.toml /
                             frpc.toml, supervises the subprocess,
                             downloads+checksums the pinned frp release

agent/                      runs on every device
  enroll.py: one-time token -> cert + api_token, persisted to state.json
  poller.py: heartbeat -> pull desired-state -> driver.apply() -> refresh
             ~/.ssh/config, on a timer
  hosts.py: the ssh_config management, isolated so it's testable without
            a real filesystem-wide ~/.ssh/config
```

## Grant wiring (the part that does the actual p2p-with-fallback)

Per `Grant`, the exposing device's frpc gets **two** proxies sharing one
secret:

```toml
[[proxies]]
name = "<grant-id>-xtcp"
type = "xtcp"
secretKey = "<grant.secret>"
localIP = "127.0.0.1"
localPort = <service.target_port>

[[proxies]]
name = "<grant-id>-stcp"
type = "stcp"
secretKey = "<grant.secret>"
localIP = "127.0.0.1"
localPort = <service.target_port>
```

and the consuming device's frpc gets **two** visitors, wired together:

```toml
[[visitors]]
name = "<grant-id>-stcp-visitor"
type = "stcp"
serverName = "<grant-id>-stcp"
secretKey = "<grant.secret>"
bindPort = -1                          # accepts fallback traffic only

[[visitors]]
name = "<grant-id>-xtcp-visitor"
type = "xtcp"
serverName = "<grant-id>-xtcp"
secretKey = "<grant.secret>"
bindAddr = "127.0.0.1"
bindPort = <consumer's persisted local port>
fallbackTo = "<grant-id>-stcp-visitor"
fallbackTimeoutMs = <settings.xtcp_fallback_timeout_ms>
```

This is entirely frp's own mechanism (`client/visitor/xtcp.go`'s
`fallbackTo`), verified live in this sandbox: xtcp hole-punching timed out
(`open tunnel timeout`) after the configured timeout, frp fell back to the
stcp visitor, and the request succeeded — then hole-punching finished in
the background a moment later, exactly as frp's own docs describe. See
`tests/integration/test_frp_e2e.py`.

**The consumer picks its own local port**, not the server — the server
doesn't know what's free on a given device, so `agent/poller.py` allocates
one the first time it sees a new `grant_id` and persists it in
`state.json` (`local_ports`), so it stays stable across restarts and
`~/.ssh/config` aliases don't shift under you. `common/models.Grant` has
no `local_port` column for this reason — it lives entirely in agent state.

## Known limitations / follow-ups

- **frpc's admin API can't tell you p2p-vs-relay for a *visitor*.**
  Checked against `fatedier/frp`'s `client/api_router.go` (dev branch):
  `/api/status` reports proxy status on the *exposing* side, there's no
  `/api/visitor-status` route. `driver.frp.FrpDriver.status()` therefore
  reports `ProxyState.UNKNOWN` for now rather than guessing. A real fix
  would tail frpc's log for the hole-punch/fallback lines (see the
  integration test's captured log for what those look like) or watch for
  an upstream API addition.
- **Real NAT hole-punching is not verified by the test suite** — the
  integration test runs over loopback, so it proves the config shape and
  the fallback mechanism, not that xtcp actually punches through two
  independent real NATs. Check that manually on real devices.
- **`server run`'s relay shutdown isn't signal-safe in all launch
  contexts** — observed during manual testing that killing the wrapping
  process (e.g. through `uv run`) doesn't always reach the `finally:
  relay.stop()` in `cli/server_cmds.py`. Under systemd (the real
  deployment path, not `uv run`) this hasn't been an issue, but it's
  worth hardening with explicit `signal.signal(SIGTERM, ...)` handling if
  it recurs.

## Gotchas hit while building this (kept here so they don't get re-learned)

- **x509 serial numbers overflow SQLite's `INTEGER`.**
  `cryptography`'s `random_serial_number()` can return up to a 160-bit
  value; SQLite's `INTEGER` is 64-bit. `Device.cert_serial` is `str`, not
  `int`.
- **`sqlite:///:memory:` needs `poolclass=StaticPool`** the moment more
  than one thread might open a connection (e.g. FastAPI's `TestClient`,
  which runs handlers in a threadpool) — otherwise each new connection
  gets its own empty in-memory database and every query 500s with "no
  such table". See `server/db.py`.
- **A server cert needs an `iPAddress` SAN, not a `dNSName` one, when
  `serverAddr` is a bare IP.** Go's TLS client won't match a `dNSName`
  entry against an IP host at all. `common/pki._san_entries` picks the
  right SAN type per entry automatically.
- **Two frpc/frps instances on one host need distinct `webServer` (admin
  API) ports** — there's no sane shared default, which is exactly why
  `admin_port` has no default in `FrpDriver`/`FrpsRelayDriver` and must be
  passed explicitly (from `Settings`, ultimately).
- **A freshly-minted `EnrollToken` for a name doesn't block a second one
  for the same name** unless you check pending (unused, unexpired) tokens
  too, not just already-enrolled `Device` rows — otherwise two unredeemed
  tokens for `wb01` can exist, and whichever redeems second dies with a
  raw DB integrity error instead of a clean conflict message. Caught by
  `tests/unit/test_web.py::test_duplicate_device_name_shows_error`.
