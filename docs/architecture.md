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
allowUsers = ["*"]                     # frp's own ACL; the real gate is the
                                        # per-grant secretKey, not this

[[proxies]]
name = "<grant-id>-stcp"
type = "stcp"
secretKey = "<grant.secret>"
localIP = "127.0.0.1"
localPort = <service.target_port>
allowUsers = ["*"]
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
Ports come from a dedicated range (`settings.agent_local_port_range_*`,
default 40000-40999), not the kernel's ephemeral range, and are
re-validated as still bindable only on the first sync cycle after a
(re)start — not every cycle, since once frpc holds the port it is
correctly "not bindable" by us and re-checking every cycle would misread
that as a collision and restart the tunnel every poll. See
`build_desired_state`'s docstring in `agent/poller.py`.

**Revocation is enforced at the control-plane only, not at the relay.**
Revoking a `Device` stops it authenticating to the control-plane API from
its next attempt on (`registry.get_device_by_api_token`); revoking a
`Grant` drops it from both sides' desired-state on their next poll, so the
agent removes the corresponding proxy/visitor from its frpc config. Ended
there: frps does not itself re-check revocation on an already-established
mTLS connection, so a device that's already connected keeps whatever it
was last configured to relay until it reconnects or the relay restarts.
Hard revocation (an already-compromised device that must be cut off
*immediately*) still means rotating the CA. See the module docstring in
`common/models.py`.

## Self-service redesign

The original design had an admin manually create every `Service` (with a
human-chosen name) and `Grant` in the WebUI, and let a non-admin "invited"
user log in to view (but not change) the dashboard. That's gone, replaced
by:

- **The WebUI is admin-only.** There is no non-admin login path at all
  (`TokenPurpose`/the invite flow were removed outright, not just hidden).
  Onboarding someone new means the admin issues their first `EnrollToken`
  with that person's email as its `created_by` (the WebUI's "Add device"
  form's owner-email field, defaulting to the admin's own account) --
  every device after that one is self-service.
- **`Service` names are now private and synthetic**
  (`svc-<device_id>-<port>`, `registry.find_or_create_service`), because
  they're no longer human-authored -- `client connect` creates them on
  demand from just (device, port). Two different owners' `connect` calls
  can never collide with each other this way (the device id is part of
  the name), but the `services.name` column is still one global unique
  index shared with admin-authored names from the WebUI's "Add service"
  form -- an admin who manually names a service `svc-<some-other-device-
  id>-<port>` can still collide with a future `connect` call, or a
  concurrent `connect`/re-enroll race can still hit the same unique index.
  Both are handled as a clean `ConflictError` (not a raw `IntegrityError`),
  not prevented up front.
- **Local "profiles" replace service names as the human-facing label.**
  A profile (`agent/state.py`'s `Profile`, keyed by a name in
  `AgentState.profiles`) is pure client-side state -- `{device_name,
  target_port}` -- created by `client connect --as <name>` (default: the
  target device's own name) and never sent to or known by the server. Two
  different devices can use different profile names for the exact same
  server-side grant; the server doesn't care. `agent/poller.py`'s
  `sync_ssh_config` resolves the `ssh <alias>` Host block from a matching
  profile when one exists, falling back to the exposing device's name
  otherwise (e.g. a grant that was set up before self-service, or via the
  admin WebUI directly).
- **Self-service device/connection endpoints** (`server/api.py`,
  `/api/agent/devices*`, `/api/agent/connect`, `/api/agent/disconnect`)
  are all scoped to the calling device's `owner_user_id` --
  `api._get_owned_device_by_name` returns 404 (not 403) for a device you
  don't own, so as not to leak whether a name belongs to someone else.
- **Accepted, not enforced**: nothing rate-limits how many `EnrollToken`s
  a device can mint via `add-device`, or how many `Service`/`Grant` rows
  it can create via `connect` (up to 65535 ports x however many devices
  you own). Given the threat model (an already-authenticated device
  spending only its own owner's rows in your own SQLite database, not a
  stranger's), this is accepted as-is rather than adding a limit that
  would only matter to an already-trusted party being unusually hostile.

## Packaging split

`frp-jump-client` and `frp-jump-server` are separate `[project.scripts]`
entry points in one package (`pyproject.toml`), with fastapi/uvicorn/
sqlmodel/jinja2/python-multipart moved to an optional `[server]` extra --
a device-only `pip install frp-jump` never imports them. There used to
also be a combined `frp-jump server/client ...` entry point
(`cli/main.py`); it was removed once the two dedicated commands existed,
since a role-agnostic third entry point that also had to conditionally
hide `server ...` on a device-only install was needless complexity once
nothing depended on it.

## Security hardening pass

An independent Opus review (see git history around this section) found
three blocking issues and several should-fix ones in the initial build,
all now fixed:

- **Authorization**: only `is_admin` users could reach fleet-mutating
  routes (`/devices/enroll-token`, `/services`, `/grants`, and the
  `/revoke` routes) -- previously any logged-in user could grant
  themselves access to any device. `server/web.py`'s `require_admin`
  dependency.
- **ssh_config injection**: device and service names are now validated
  against a strict charset (`registry._NAME_RE`) before they can reach
  `agent/hosts.py`'s generated `~/.ssh/config` -- previously an
  unsanitized name (e.g. containing a newline) could inject a
  `ProxyCommand` block, i.e. RCE on the consuming device, reachable from
  any logged-in session before the authorization fix above.
- **Agent resilience**: `fetch_desired_state`/`send_heartbeat` previously
  only turned a non-2xx *response* into `SyncError`; a transport-level
  failure (DNS, connection refused, timeout -- `httpx.HTTPError`'s tree,
  not caught by the same `except`) propagated raw and killed
  `run_forever`. Both now wrap transport errors into `SyncError`, and
  `run_forever` also catches bare `Exception` as a last resort so a bug
  elsewhere in the cycle can't kill the daemon either.
- **Non-atomic `state.json` write**: truncate-then-write on the device's
  only copy of its private key/cert/api_token, on every newly-seen grant.
  Now write-temp + fsync + `os.replace`. See `agent/state.save`.
- **No revocation path** -- see the "Grant wiring" section above.
- **SQLite `foreign_keys` was never enabled** -- every `foreign_key=` in
  `common/models.py` was decorative; `server/db.py` now sets
  `PRAGMA foreign_keys=ON` on connect, and `registry.create_service`/
  `create_grant` also validate the referenced rows exist up front for a
  clean `NotFoundError` instead of a raw `IntegrityError`.
- **Private keys written world-readable** (`chmod` after `write_bytes`,
  briefly readable under the default umask) in `driver/frp/driver.py` and
  `server/bootstrap.py` -- both now use `common.pki.write_private_key`,
  which opens with mode `0600` from creation.
- **Session cookie's `Secure` flag** was keyed only off
  `request.url.scheme`, which is always `"http"` in the documented
  TLS-terminating-reverse-proxy deployment (uvicorn itself never sees
  TLS) -- silently losing `Secure` on a 30-day cookie. Now also trusts
  `settings.public_base_url` starting with `https://`.
- **Login tokens in access logs**: `GET /auth/<token>` would otherwise
  write the raw token to uvicorn's access log on every visit. `server run`
  now passes `access_log=False`.
- Added the highest-value missing test: `frps` actually rejecting a
  client cert that chains to a different CA
  (`test_frps_rejects_a_client_whose_cert_chains_to_a_different_ca`) --
  the core "an unenrolled device cannot reach the relay at all" claim was
  previously only asserted in prose.

**Still open** (reviewed, accepted as-is for now): `ensure_installed`'s
checksum file is fetched from the same host/connection as the binary it
verifies, so it only guards against corruption/truncation, not a
compromised connection or release -- `driver/frp/binaries.py`'s module
docstring now says so explicitly instead of overclaiming. A concurrent
enroll of the same one-time token twice can still hit a raw
`IntegrityError` (very low practical likelihood; single-use token race).

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
