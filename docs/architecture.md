# Architecture

This mirrors the original implementation plan, updated for what actually
got built and a few things learned along the way. See the module layout in
the README first if you haven't already.

## Data flow

```
server/                     control-plane: source of truth
  mini-CA (common/pki.py)   issues device certs on enroll
  SQLite (common/models.py) users (identified by an SSH public key),
                             devices, services, grants, enroll tokens,
                             enroll challenges
  server/api.py              agent-facing: enroll (token or key-based
                             challenge/response), heartbeat, desired-state
                             pull, every self-service device/connection
                             endpoint (bearer-token auth throughout)
  frps managed through the same driver abstraction as frpc

driver/                     abstract TunnelDriver / RelayDriver
  frp/                      concrete implementation: renders frps.toml /
                             frpc.toml, supervises the subprocess,
                             downloads+checksums the pinned frp release,
                             reads relayed-traffic counters off frps's
                             own admin API

agent/                      runs on every device
  enroll.py: one-time token, or a signed challenge over an already-
             registered SSH key -> cert + api_token, persisted to state.json
  poller.py: heartbeat -> pull desired-state -> driver.apply() -> refresh
             ~/.ssh/config, on a timer, with exponential backoff on failure
  hosts.py: the ssh_config management, isolated so it's testable without
            a real filesystem-wide ~/.ssh/config
  service_install.py: writes + enables the systemd unit for `client run`
```

There is no WebUI or web-facing admin surface of any kind. Administration
is entirely `frp-jump-server` CLI commands, run over SSH to the box —
SSH access to that box *is* the admin authorization boundary, the same
way it always was for anything else you'd manage there.

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

**Disabling is enforced at the control-plane only, not at the relay.**
`Device.enabled = False` does *not* stop the device authenticating to the
control-plane API (`registry.get_device_by_api_token` doesn't check it)
-- it still heartbeats and pulls desired-state, which is deliberate: a
disabled device needs to keep polling so it notices being re-enabled
later. What it *does* do: its desired-state (both what it exposes and
what it consumes) goes empty on its next poll, so its agent tears down
every proxy/visitor in its frpc config; and every *mutating* self-service
route (`server/api.py`'s `get_enabled_device` dependency) starts
rejecting its bearer token with 403 -- so a disabled device's still-valid
token cannot be used to re-enable itself, rotate the owner's key, delete
another of the owner's devices, or open a new connection. Only another
still-enabled device of the same owner, or the admin CLI, can flip it
back. None of this touches frps/mTLS directly: a device that's already
connected keeps whatever it was last configured to relay until it
reconnects or the relay restarts. `delete_device`/`delete_user` are the
only irreversible operations; a compromised device that must be cut off
*immediately*, not just on its next poll, still means rotating the CA.
See the module docstring in `common/models.py`.

## Identity and enrollment (SSH-key based)

A `User` is identified by an SSH public key (`ssh_public_key`, a unique
`ssh_key_fingerprint` computed by `common/ssh_signing.fingerprint`, and a
friendly `label` for admin use) -- there is no email or password anywhere
in this system. An admin registers someone once, over SSH to the box:

```sh
frp-jump-server users add-key alice_key.pub --label alice
```

From there, every device that person enrolls can either present a
one-time `EnrollToken` (the classic flow, unchanged in shape --
`enroll-tokens create`/self-service `devices add-token`), or prove
possession of the already-registered private key directly, with no token
at all:

1. `POST /api/agent/enroll/challenge {public_key}` -- always returns a random nonce
   (`EnrollChallenge`, a short-lived DB row --
   `settings.enroll_challenge_ttl_seconds`, default 120s), whether or not
   that key's fingerprint is actually registered
   (`registry.create_enroll_challenge`). Whether it is only becomes
   visible at the next step, where an unknown fingerprint fails exactly
   like a bad signature -- a 200-vs-404 split here, however worded, would
   itself be an oracle for which keys the server knows about. Outstanding
   challenges per fingerprint are capped and expired ones opportunistically
   purged on each call, since this route is unauthenticated by design.
2. The client signs the nonce locally: `ssh-keygen -Y sign -f
   <private-key> -n frp-jump-enroll <nonce-file>` (`common/ssh_signing
   .sign`) -- the private key never leaves the device.
3. `POST /api/agent/enroll/by-key {challenge_id, signature, requested_name}` --
   server verifies with `ssh-keygen -Y verify` against the *stored*
   public key (`registry.redeem_enroll_challenge`), and on success creates
   the `Device` exactly like `redeem_enroll_token` does. Consumption is an
   atomic conditional `UPDATE ... WHERE used_at IS NULL` (same for
   `EnrollToken`), not a read-then-write -- two concurrent redemptions of
   the same token/challenge could otherwise both pass validation and each
   create a device before either committed.

Both `ssh-keygen -Y sign`/`-Y verify` calls shell out to the real OpenSSH
client (the same mechanism git uses for SSH-signed commits) -- no
crypto library reimplements this. `-n frp-jump-enroll` namespaces the
signature so it can never be replayed as, say, a git-commit signature or
vice versa.

A user can rotate their key at any time -- `frp-jump-server users
set-key <label> <new-key.pub>` (admin recovery, trusted by construction:
an operator with shell access on the box) or self-service
`frp-jump-client set-key <new-private-key-path>` (bearer-authed via any
of their own enrolled devices). The self-service path is a signed
challenge/response round trip too, same shape as key-based enrollment
above (`POST /api/agent/users/set-key/challenge {public_key}` then `POST
/api/agent/users/set-key {challenge_id, signature}`, `registry
.create_key_rotation_challenge`/`redeem_key_rotation_challenge`) --
a bearer token alone must not be enough to repoint the account at a key
nobody has proven they actually hold.

## Device/grant lifecycle

- **`enable`/`disable`** (`Device.enabled`) is the *reversible* state --
  see "Disabling is enforced..." above. `delete` is the only irreversible
  one (cascades to the device's own services/grants, frees its name).
  There is no separate "revoke" concept for either a device or a grant
  any more -- a grant that should go away is just deleted
  (`registry.delete_grant`), full stop.
- **Device names are unique per-owner, not globally**
  (`UniqueConstraint(owner_user_id, name)` on `devices`) -- two different
  people can each enroll a device called "laptop". Every lookup that
  resolves a device by name (`registry.get_device_by_name`,
  `_check_name_free`) takes the owner id explicitly; the admin CLI's
  mutating `devices` subcommands (`delete`/`disable`/`enable`) require
  `--user` for exactly this reason -- an unqualified name would otherwise
  be ambiguous across owners.
- **Self-service disconnect can target any of the caller's own devices**,
  not just the calling one -- `DisconnectRequest.consumer_device_name`
  (`client disconnect --from OTHER-DEVICE`) resolves that other device
  the same ownership-scoped way as everything else, then deletes the
  grant on its behalf. Useful for tearing down a connection you notice
  was left up on a different device of yours.
- **`Service` names are private and synthetic**
  (`svc-<device_id>-<port>`, `registry.find_or_create_service`), created
  on demand by `client connect` from just (device, port) -- never
  human-authored or shown to anyone. There is no admin path that creates
  a `Service` directly any more (`registry.create_service` exists purely
  for direct unit-testing of the lower-level registry function). The
  `services.name` column is still one global unique index, so a
  concurrent `connect`/re-enroll race can in principle still hit it --
  handled as a clean `ConflictError`, not a raw `IntegrityError`.
- **Local "profiles" replace service names as the human-facing label.**
  A profile (`agent/state.py`'s `Profile`, keyed by a name in
  `AgentState.profiles`) is pure client-side state -- `{device_name,
  target_port}` -- created by `client connect --as <name>` (default: the
  target device's own name) and never sent to or known by the server. Two
  different devices can use different profile names for the exact same
  server-side grant; the server doesn't care. `agent/poller.py`'s
  `sync_ssh_config` resolves the `ssh <alias>` Host block from a matching
  profile when one exists, falling back to the exposing device's name
  otherwise (e.g. a grant that was set up directly via the admin CLI).
- **Self-service device/connection endpoints** (`server/api.py`,
  `/api/agent/devices*`, `/api/agent/connect`, `/api/agent/disconnect`)
  are all scoped to the calling device's `owner_user_id` --
  `api._get_owned_device_by_name` returns 404 for a device you don't own,
  so as not to leak whether a name belongs to someone else (per-owner
  name scoping means it can no longer even leak *that* the name is taken
  by a stranger -- your own devices are the only namespace you can
  observe at all). Every *mutating* self-service route additionally
  depends on `get_enabled_device`, not just `get_current_device` -- see
  "Disabling is enforced..." above.
- **Accepted, not enforced**: nothing rate-limits how many `EnrollToken`s
  a device can mint via `devices add-token`, or how many `Service`/`Grant`
  rows it can create via `connect` (up to 65535 ports x however many
  devices you own). Given the threat model (an already-authenticated
  device spending only its own owner's rows in your own SQLite database,
  not a stranger's), this is accepted as-is rather than adding a limit
  that would only matter to an already-trusted party being unusually
  hostile.

## Relayed-traffic visibility (deliberately relay-only)

`frp-jump-server users show`/`devices list` show a compact "relayed
today: X in / Y out" figure per connection, sourced from frps's own local
admin API (`driver.frp.driver.fetch_proxy_traffic`, `GET /api/proxy/stcp/
<name>` on `127.0.0.1:{frps_admin_port}`). This is deliberately scoped to
*relayed* traffic only, not total traffic, for a reason grounded in
frp's own source (`fatedier/frp`, checked directly): every grant's `stcp`
proxy always has its data flow through frps by construction, and frps
does track bytes for it (`server/proxy/proxy.go`'s
`handleUserTCPConnection`, shared by `tcp`/`http`/`stcp`, calls
`metrics.Server.AddTrafficIn/Out`). A grant's `xtcp` proxy, when hole-
punching succeeds, carries its data directly between the two frpc
processes -- entirely bypassing frps -- and `server/proxy/xtcp.go` never
calls that same accounting code at all. Neither frps nor frpc tracks
xtcp/p2p traffic anywhere. So a genuinely peer-to-peer connection reports
zero here even while carrying real traffic; this is a limitation of what
frp itself exposes, not a bug in this project, and the CLI's own docstring
(`cli/server_cmds._relayed_today`) says so. Building true total-traffic
accounting would mean OS-level byte counting on the local bound ports
instead -- a materially bigger feature, not implemented.

## Packaging split

`frp-jump-client` and `frp-jump-server` are separate `[project.scripts]`
entry points in one package (`pyproject.toml`), with fastapi/uvicorn/
sqlmodel moved to an optional `[server]` extra -- a device-only `pip
install frp-jump` never imports them (jinja2/python-multipart were also
in that extra before the WebUI was removed; gone now too, nothing needs
them). There used to also be a combined `frp-jump server/client ...`
entry point (`cli/main.py`); it was removed once the two dedicated
commands existed, since a role-agnostic third entry point that also had
to conditionally hide `server ...` on a device-only install was needless
complexity once nothing depended on it.

## Security hardening pass (0.2.0, WebUI-era)

Historical record from before the WebUI was removed (0.3.0) -- kept for
context on what was already reviewed and fixed once; `server/web.py`/
`require_admin`/the session cookie no longer exist, see "Identity and
enrollment" and "Device/grant lifecycle" above for the current model. An
independent Opus review (see git history around this section) found
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
  an upstream API addition. Related but distinct from the "Relayed-traffic
  visibility" section above: that one at least gives an authoritative
  *relayed-bytes* signal from frps directly, it just can't distinguish
  "genuinely p2p" from "no traffic yet".
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
  raw DB integrity error instead of a clean conflict message. Covered by
  `tests/unit/test_registry.py::test_create_enroll_token_rejects_duplicate_name_while_unredeemed_token_exists`.
