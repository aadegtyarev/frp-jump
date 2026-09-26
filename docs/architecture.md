# Internals

For people changing the code. If you want to understand what frp-jump does
rather than how it is built, read [How it works](how-it-works.md) first.

## Module map

```
src/frp_jump/
  common/     settings, DB models, private CA, opaque tokens, SSH signing
  driver/     TunnelDriver / RelayDriver protocols
    frp/      the only code that knows it's frp underneath
  server/     registry (CRUD), agent-facing API, bootstrap, systemd install
  agent/      enroll, sync loop, local state, ssh_config, systemd install
  cli/        frp-jump-server / frp-jump-client entry points
```

`tests/unit/` mirrors this roughly one to one. `tests/integration/` holds the
tests that download real frp binaries, behind the `integration` marker.

## The four rules this codebase follows

**No hardcoded configuration.** Ports, TTLs, version pins, and paths live in
`common/settings.py` and flow in as parameters. Nothing reads a module-level
constant deep in the call stack.

**The tunneling engine stays behind the abstraction.** `driver/base.py` defines
`TunnelDriver` and `RelayDriver` as Protocols. Only `driver/frp/` knows what frp
is. If you are reaching for an frp concept outside that package, something is in
the wrong place.

**`registry.py` is framework-agnostic.** It takes a plain SQLModel `Session`,
never a FastAPI `Request`. That is what lets it be unit-tested without starting
the app.

**Data crossing a boundary is a dataclass, not an ORM row.** See
`registry.ExposedGrantView` and friends. The database schema stays free to
change without rippling into JSON shapes.

## Decisions worth knowing

### The agent allocates local ports, not the server

The server has no idea what is free on a given device. `agent/poller.py` picks a
port the first time it sees a new grant id and persists it in `state.json`, so
it survives restarts and ssh aliases stay stable. `Grant` has no `local_port`
column for exactly this reason.

Ports come from a dedicated range (default 40000-40999), not the kernel's
ephemeral range — the kernel could otherwise hand the same port to an unrelated
outbound connection later.

They are re-validated as bindable only on the first sync cycle after a restart.
Not every cycle: once frpc holds the port, it is correctly "not bindable" by us,
and re-checking would read that as a collision and restart the tunnel on every
poll. See `build_desired_state`'s docstring.

### Disabling is a control-plane action, by design

`Device.enabled = False` does not stop the device authenticating.
`registry.get_device_by_api_token` deliberately keeps accepting it, so a
disabled device keeps polling and can notice being re-enabled.

What it does: desired state goes empty on the next poll, and every mutating
route rejects the token via the `get_enabled_device` dependency. A disabled
device's still-valid token cannot re-enable itself, rotate the owner's key,
delete a sibling device, or open a connection.

None of this reaches frps or mTLS. Hard, immediate revocation means rotating the
CA. This is stated for users in [Security model](security.md#turning-a-device-off).

### Device names are unique per owner

`UniqueConstraint(owner_user_id, name)`. Two people can each have a `laptop`.
Every lookup that resolves a device by name takes the owner id explicitly, and
the admin CLI's mutating `devices` subcommands require `--user` — an unqualified
name would be ambiguous.

### Services are synthetic and private

`svc-<device_id>-<port>`, created on demand by `connect` from just (device,
port). Never human-authored, never displayed. There is no admin path that
creates one directly; `registry.create_service` exists for unit tests of the
lower-level function.

`services.name` is still one global unique index, so a concurrent
`connect`/re-enroll race can hit it. That surfaces as a clean `ConflictError`,
not a raw `IntegrityError`.

### Profiles are client-side only

`agent/state.Profile` is `{device_name, target_port}` under a local name. The
server never sees it. Two devices can call the same grant different things.
`sync_ssh_config` resolves the ssh alias from a matching profile, falling back
to the exposing device's name for a grant created some other way.

### Challenge redemption is an atomic conditional update

Both `EnrollToken` and `EnrollChallenge` are consumed with
`UPDATE ... WHERE used_at IS NULL`, not read-then-write. Two concurrent
redemptions could otherwise both pass validation and each create a device before
either committed.

### The enroll challenge endpoint is deliberately uninformative

`POST /api/agent/enroll/challenge` returns a nonce whether or not the fingerprint is
registered. An unknown key fails at the redeem step, exactly like a bad
signature. A 200-vs-404 split would be an oracle for which keys the server
knows. Outstanding challenges per fingerprint are capped, and expired ones are
purged opportunistically, since the route is unauthenticated by design.

### Client account selection is continuity-first

`agent/service_install.resolve_default_target` prefers an auto-created
`frp-jump-client` system account — but only when nothing is enrolled yet at the
traditional location. Reusing existing state always beats picking a "better"
account, so a later `sudo install-service` can never orphan an earlier
unprivileged `enroll`.

It also falls back rather than failing when the dedicated account cannot execute
the binary at all (`_world_traversable` — a venv under a `0750` home directory,
increasingly common on newer distros). An explicit `--system-user` fails loudly
instead, because that one is a deliberate request.

### Accepted, not enforced

Nothing rate-limits how many enroll tokens a device mints, or how many services
and grants it creates. The threat model is an already-authenticated device
spending rows in its own owner's database on your own server. A limit here would
only inconvenience an already-trusted party being unusually hostile.

## Gotchas

Each of these cost someone an afternoon once.

| Thing | Why it bites |
| --- | --- |
| `Device.cert_serial` is `str`, not `int` | `cryptography`'s `random_serial_number()` returns up to 160 bits. SQLite's `INTEGER` is 64 |
| `sqlite:///:memory:` needs `poolclass=StaticPool` | FastAPI's `TestClient` runs handlers in a threadpool. Without it, each connection gets its own empty database and every query 500s with "no such table". See `server/db.py` |
| A bare-IP `serverAddr` needs an `iPAddress` SAN | Go's TLS client will not match a `dNSName` entry against an IP host. `common/pki._san_entries` picks the right type per entry |
| Device certs get `CLIENT_AUTH` only | Only `bootstrap.load_or_create_relay_cert` passes `server_auth=True`. A device cert that could also present as the relay would let an on-path device impersonate it |
| Only the server-side driver enables an admin API | `FrpDriver` never turns on frpc's `webServer`. `FrpsRelayDriver` needs a distinct `admin_port` per instance, which is why it has no default |
| A pending enroll token blocks a second one for the same name | Check unused, unexpired tokens as well as existing `Device` rows, or the second redemption dies with a raw integrity error. Covered by `test_create_enroll_token_rejects_duplicate_name_while_unredeemed_token_exists` |
| The API hides what it is | `server/app.py` serves a placeholder at `/` and disables `/docs`, `/redoc`, `/openapi.json`. A relay box is internet-reachable by construction |

## Known limitations

**The frp checksum comes from the same host as the binary.**
`driver/frp/binaries.py` fetches both from the same GitHub release over the same
connection. It guards against corruption, not against a compromised connection
or release. Fixing it properly means pinning per-architecture digests next to
`frp_version` in settings.

**frpc cannot tell us whether a visitor went peer-to-peer.** Checked against
`fatedier/frp`'s `client/api_router.go`: `/api/status` covers proxies on the
exposing side, and there is no visitor equivalent. `FrpDriver.status()` reports
`ProxyState.UNKNOWN` rather than guessing. A real fix means tailing frpc's log
for the hole-punch and fallback lines, or waiting for an upstream API.

**Relayed-traffic figures are relay-only, and that is structural.** Every
grant's `stcp` proxy flows through frps, which does account for it
(`server/proxy/proxy.go`'s `handleUserTCPConnection`). The `xtcp` proxy, when
hole-punching succeeds, carries data directly between two frpc processes, and
`server/proxy/xtcp.go` never calls that accounting code. Neither side tracks it
anywhere. True total-traffic accounting would mean OS-level byte counting on the
local bound ports — a materially bigger feature.

**Real NAT hole-punching is not covered by tests.** The integration test runs
over loopback. It proves the config shape and the fallback mechanism, not
traversal across two independent NATs. Verify that by hand on real devices.

**`server run`'s relay shutdown is not signal-safe everywhere.** Killing a
wrapping process (`uv run`, for instance) does not always reach the
`finally: relay.stop()` in `cli/server_cmds.py`. Under systemd, the real
deployment path, this has not come up. Worth hardening with an explicit
`signal.signal(SIGTERM, ...)` if it recurs.

## Packaging

`frp-jump-client` and `frp-jump-server` are two `[project.scripts]` entry points
in one package. FastAPI, uvicorn, SQLModel, and `cryptography` live in an
optional `[server]` extra, so a device install never imports them.

`cryptography` in particular has no prebuilt wheel on some platforms and needs a
Rust toolchain to build from source. Keeping it off the client's dependency
chain is worth it for that alone. `common/crypto.py`'s `write_private_key` —
which the client does use — is deliberately dependency-free for the same reason,
rather than living next to `common/pki.py`.

The `.deb` bundles its own Python 3.12 under `/opt/frp-jump-client`, built per
architecture through `docker buildx` with QEMU. See
[`packaging/deb/build.sh`](../packaging/deb/build.sh).

## See also

- [CONTRIBUTING.md](../CONTRIBUTING.md) — setup, tests, conventions.
- [How it works](how-it-works.md) — the user-facing explanation.
