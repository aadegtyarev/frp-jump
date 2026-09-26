# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/); versions will
follow [SemVer](https://semver.org/) once something is tagged/released.

## [Unreleased]

## [0.3.4] - 2026-09-26

Found by an independent Fable review focused on compromise/blast-radius
resilience, since this project brokers real network access to controller
hardware.

### Fixed

- **High: a compromised device could pivot into any sibling device (and
  its LAN) via frpc's own unauthenticated admin API.** Every client
  device's frpc enabled a `webServer` (admin API) on `127.0.0.1` with no
  password, which nothing in this codebase ever read -- but which any
  other device of the same owner could already reach through a normal
  `connect`, and use to rewrite that sibling's tunnel config or kill its
  frpc entirely. Removed: the client side never enables it now (the
  server side still does, and still needs it, for relayed-traffic
  visibility).
- **High: `set-key` let a bearer token from a single compromised device
  permanently hijack the whole account.** Self-service key rotation only
  proved possession of the *new* key; a compromised device's own bearer
  token plus a freshly-generated attacker keypair was enough to repoint
  the owner's registered key, locking the real owner out for good.
  `frp-jump-client set-key` now takes a second argument (your *current*
  private key) and the server requires proof of both before rotating --
  a breaking CLI change, but a necessary one.

### Added

- **"Ports and firewalls"** section in the README: which ports the
  server needs open inbound, what the client needs outbound, and how a
  restrictive firewall affects (but doesn't break) p2p hole-punching.

### Changed

- README and `docs/architecture.md` rewritten for clarity -- shorter
  paragraphs, and historical/superseded content (a security pass from
  the pre-0.3.0 WebUI era, an already-fixed concurrent-enrollment race)
  removed in favor of describing only current behavior.

## [0.3.3] - 2026-09-26

### Added

- **Protocol version reporting**: an unauthenticated `GET /api/agent/version` route
  on the server, and a matching `frp-jump-client doctor` check, so a
  client and server that fall out of sync (a breaking wire-protocol
  change down the line) detect the mismatch explicitly instead of
  misbehaving. On a mismatch the agent skips applying that cycle's
  desired state entirely (leaves any running tunnel untouched) and keeps
  retrying via the existing backoff loop -- it never tears down a
  working connection or crashes over a version skew.
- **apt repository**: a signed apt repo, published to GitHub Pages on
  every release, as an alternative to `pip install` -- see "Installing
  the CLI" in the README. Individual `.deb` downloads from GitHub
  Releases remain available as a fallback.
- **`--poll-interval`**: `frp-jump-client run --poll-interval SECONDS`
  overrides `agent_poll_interval_seconds` (now defaulting to 2s, down
  from 30s) for one run without touching persisted config.

### Changed

- **p2p/relay tunnel payloads are now encrypted** (`transport.useEncryption`
  on every xtcp/stcp proxy and visitor). Previously only the frpc<->frps
  control channel used mTLS; the actual tunneled traffic between two
  devices (p2p or relayed) went over the wire unencrypted unless the
  tunneled protocol encrypted itself (e.g. already-TLS'd traffic).
- Files rewritten on every poll cycle (TLS certs, the managed
  `~/.ssh/config` block, frpc/frps TOML configs) are now skipped when
  their content hasn't actually changed, to avoid unnecessary flash
  writes on embedded devices now that polling is 15x more frequent by
  default.

## [0.3.2] - 2026-09-26

Found by a second, broader independent review (security + module/class
design) run right after 0.3.1 shipped, plus real-world testing on a
second machine.

### Added

- **`--system-user`**: both `frp-jump-client enroll`/`install-service`
  and the new `frp-jump-server install-service` can now run isolated
  under a dedicated, unprivileged system account (created automatically,
  no login shell, its own `/var/lib/<name>`) instead of root or a real
  person's own account -- least-privilege, matching how this project's
  own server deployments already run.
- **`frp-jump-server install-service [--system-user NAME]
  [--relay-public-addr ADDR]`**: one-shot automated setup -- creates the
  system user, bootstraps the CA/database, writes
  `/etc/frp-jump/<name>.env`, and installs + starts a hardened systemd
  unit (`ProtectSystem=strict`, `NoNewPrivileges=yes`, a single writable
  data directory). Previously this had to be done by hand.

### Fixed

- **High: deleting a device (or its owner) crashed with a foreign-key
  `IntegrityError`** once that device had ever called `set-key` --
  `KeyRotationChallenge.device_id` is an enforced FK that `delete_device`
  never cleared. The device and its owner became permanently
  undeletable through any admin or self-service path.
- **High: `connect --local-port N` was silently ignored, and the wrong
  port was reported, whenever `run` was already looping.** `sync_once`
  only reloaded `profiles` from disk (the 0.2.1 fix), not `local_ports`
  -- a pin written by a separate `connect` invocation was invisible to
  the running daemon's in-memory copy, which allocated and saved over
  it on its very next cycle. Both fields are now reloaded together.
- **`sudo <full-path-to-frp-jump-client> install-service` could still
  fail** two different ways after the 0.3.1 fix: `resolve_exec_path`
  re-searched `PATH` (sudo's restricted `secure_path`) instead of
  trusting the exact path it was just invoked with, and
  `install-service`'s own pre-flight enrollment check used a plain
  `Settings()` instead of the same `$SUDO_USER`-aware resolution
  `install` itself already used -- both hit on a real second-machine
  install this session. `install-service --help` also now says outright
  that `--user` mode stops on logout unless `loginctl enable-linger` is
  set up.
- **The client no longer depends on `cryptography` at all.** It was
  pulled in only for `write_private_key`, a plain `os.open`/`os.write`
  helper that happened to live in the same module as the server's real
  x509/CA code (`common/pki.py`) -- moved to dependency-free
  `common/crypto.py`, and `cryptography` moved to the `[server]` extra.
  `cryptography` has no prebuilt wheel on some platforms (e.g.
  Termux/Android) and needs a Rust toolchain to build from source; a
  plain `pip install frp-jump` no longer needs either.
- `frpc.toml`/`frps.toml` (every grant's `secretKey`) were written with
  the default umask (typically world-readable); now written the same
  restrictive-from-creation way as `tls.key` already was.

## [0.3.1] - 2026-09-26

Two real-world rough edges hit within hours of 0.3.0 shipping, both around
`enroll`-unprivileged-then-`install-service`-via-`sudo`:

### Fixed

- `sudo frp-jump-client install-service` failed with "command not found"
  when installed via `pip install --user`/pipx -- `sudo`'s own
  `secure_path` never includes a per-user install location. `enroll`'s
  printed hint now substitutes the resolved absolute path for the `sudo`
  variant specifically, so copy-pasting it always works; `install-service
  --help` documents the `sudo $(which frp-jump-client) ...` workaround
  too.
- `sudo frp-jump-client install-service` (or `sudo $(which ...)`) could
  itself report "not enrolled" even right after a successful unprivileged
  `enroll` -- its own pre-flight check used a plain `Settings()`, which
  under `sudo`'s default `env_reset` resolves `$HOME` to root's, not the
  invoking person's. `install-service`'s check now shares the same
  `$SUDO_USER`-aware home resolution `service_install.install` already
  used internally (`client_cmds._settings_for_service_ops`), so the two
  agree on where state lives.
- `install-service --user`'s help text and console output now say
  outright that it stops on logout unless `sudo loginctl enable-linger
  $(whoami)` is also run once -- previously only mentioned in a
  docstring nobody reading `--help` would see.

## [0.3.0] - 2026-09-26

**Breaking.** The WebUI, email/password accounts, and device/grant
"revoke" are all gone. If you're upgrading a running server: back up its
database, then let it recreate the schema from scratch (there is no
migration path from the old `User.email`/`Session`/`LoginToken` tables) --
re-register users with `users add-key` and re-enroll every device. Config
keys `webui_host`/`webui_port` are renamed to `api_host`/`api_port`;
`login_token_ttl_minutes`/`session_ttl_days` are gone.

### Added

- **SSH-key-based identity and enrollment.** A `User` is now identified by
  an SSH public key, not an email/password account:
  `frp-jump-server users add-key <pubkey-file> [--label X]` registers
  someone once, and every device they enroll after that can prove
  possession of that key directly (`frp-jump-client enroll <url>
  <private-key-path> --name X`, a challenge/response round trip signed
  locally with `ssh-keygen -Y sign`/verified server-side with
  `ssh-keygen -Y verify` -- see `common/ssh_signing.py`) -- no token
  needed at all. The classic one-time `EnrollToken` flow still exists
  alongside it, for a device without the key on it. `frp-jump-server
  users set-key` / self-service `frp-jump-client set-key` rotate a lost
  or replaced key.
- **`frp-jump-server` admin CLI**, replacing the WebUI entirely: `users
  add-key/set-key/list/show/delete`, `devices list/delete/disable/enable`,
  `enroll-tokens create/list/revoke`. Every mutating `devices` subcommand
  requires `--user` (see "per-owner device names" below).
- **`enable`/`disable`** (`frp-jump-server devices disable/enable --user
  X`, self-service `frp-jump-client devices disable/enable`) replaces the
  old "revoke": tears down and blocks new connections, reversibly, without
  losing the device's enrollment -- it keeps polling and picks back up
  the moment it's re-enabled. `delete` is now the only irreversible
  device/grant operation.
- **`frp-jump-client install-service [--user]`**: installs and enables
  the systemd unit for `client run` (system-wide, needs root, or under
  your own account with `--user`). `enroll` runs this automatically when
  invoked as root.
- **`connect`/`disconnect` UX**: `connect` drops `--protocol` in favor of
  auto-classifying SSH by well-known port (22, 2222) or an explicit
  `--ssh` flag -- there's no other functional protocol distinction to
  make. New `--local-port` pins the local bound port instead of picking
  one automatically. `disconnect --from OTHER-DEVICE` tears down a
  connection made from a *different* one of your own devices (with a
  confirmation prompt, skippable with `-y`) -- for when you notice a
  forgotten connection on another device in `devices list`.
- **Relayed-traffic visibility**: `frp-jump-server users show`/`devices
  list` show a compact "relayed today: X in / Y out" figure per
  connection, read from frps's own admin API. Deliberately relay-only --
  a genuinely peer-to-peer (xtcp) connection's traffic is invisible to
  frp itself (verified against frp's own source, see
  `docs/architecture.md`), so this can never show a p2p connection's
  actual volume, only what really went through the relay.
- Agent hardening: `client run`'s sync loop retries a failed cycle
  (server unreachable, network down) with exponential backoff (5s up to
  90s) instead of a fixed interval, resetting to normal cadence once a
  cycle succeeds -- and never exits the process, so systemd never needs
  to restart it. The same tolerance applies to the one-time frp binary
  download at startup.

### Changed

- Device names are unique per-owner now, not globally -- two different
  people can each have a device called "laptop". Every admin CLI command
  that names a device (`devices delete/disable/enable`) requires `--user`
  for exactly this reason.
- `client devices` replaces the old bare `add-device`/`list`/
  `delete-device` commands: `devices add-token` (renamed from
  `add-device`), `devices list`, `devices delete`, plus new `devices
  disable`/`devices enable`.
- `client enroll`'s second argument is now either a one-time token or a
  private-key path (auto-detected) -- `TOKEN_OR_KEYFILE`, not just
  `TOKEN`.

### Removed

- The WebUI, entirely (`server/web.py`, `server/auth.py`,
  `server/templates/`) -- administration is 100% `frp-jump-server` CLI
  run over SSH to the box now. `server init` no longer takes
  `--admin-email`; `server login-link` is gone (nothing to log in to).
  `jinja2`/`python-multipart` dropped from the `[server]` extra.
  `packaging/scripts/frp-jump-login-link` deleted (wrapped a command that
  no longer exists).
- `revoke_device`/`revoke_grant` and the `Device.revoked_at`/
  `Grant.revoked_at` columns -- see `enable`/`disable` above.

### Security

Found and fixed by an independent Opus review of this release before it
shipped:

- **Critical: a multi-line "key" blob could enroll as someone else's
  account.** `ssh-keygen -l` only ever fingerprints the *first* key in a
  file, but `-Y verify`'s allowed-signers file matches any line in it --
  so a crafted two-line input (a victim's public key, plus an attacker's
  on a second line) fingerprinted as the victim while actually
  authenticating with the attacker's key, letting an attacker enroll a
  device into the victim's account after registering that blob via
  `set-key`. `common/ssh_signing.py` now canonicalizes (and rejects any
  embedded newline in) every key before fingerprinting *or* verifying it;
  every registry entry point that stores a key goes through the same
  check.
- **Critical: `/users/set-key` required no proof of possession of the new
  key.** A bearer token alone was enough to repoint an account at any
  public key an attacker could name (e.g. harvested from
  `github.com/<user>.keys`) -- including as a way to persist access after
  the device that leaked the token was deleted or disabled. Key rotation
  is now a signed challenge/response round trip, same shape as key-based
  enrollment (`/users/set-key/challenge` then `/users/set-key`; `client
  set-key` now takes a private-key path, not a bare public key file).
- **High: one-time enroll tokens and key challenges were redeemable
  twice under concurrent requests.** Redemption read `used_at IS NULL`
  and wrote it back separately, so two racing redemptions could both
  pass the check and each create a device before either committed.
  Consumption is now one atomic conditional `UPDATE ... WHERE used_at IS
  NULL`, sharing the same commit as the device it creates.
- **High: `install-service` run via `sudo` pointed the daemon at
  `/root`.** `sudo` sets `$HOME=/root` by default, so a system-wide
  install after an unprivileged `enroll` looked for state in the wrong
  place and restart-looped forever, finding nothing. `install`/`enroll`
  now resolve the real invoking user via `$SUDO_USER` and set `User=` on
  the generated unit accordingly (a genuine root login is unaffected).
- **Medium**: `ssh-keygen` subprocess calls (reachable from the
  unauthenticated `/enroll/challenge` route) now have a timeout, so a
  stuck invocation can't pin a request-handling thread indefinitely.
  `/enroll/challenge` now always issues a syntactically valid challenge
  regardless of whether the key is registered -- rejection only happens
  at redemption, indistinguishable from a bad signature -- since the
  200-vs-404 split was itself an enumeration oracle no matter how the
  error text read. Outstanding challenges per fingerprint are now capped
  and expired ones opportunistically purged, since that route has no
  auth to otherwise bound how many it accumulates.
- A disabled device's still-valid bearer token could call
  `/devices/{self}/enable` and re-enable itself, or `/users/set-key`,
  `/devices/{other}/delete`, `/devices/enroll-tokens`, and `connect`/
  `disconnect` -- defeating the entire point of `disable` for a
  suspected-compromised device. Every *mutating* self-service route now
  depends on a new `get_enabled_device` (not just `get_current_device`),
  which rejects a disabled device's token with 403; only heartbeat and
  desired-state (both read-only, and desired-state already goes empty
  while disabled) stay reachable with it.

## [0.2.1] - 2026-09-26

### Fixed

- `client run`'s long-lived agent process loaded `state.json` once at
  startup and kept it in memory; a separate `client connect`/`disconnect`/
  `delete-device` invocation (a different process) writing a new profile
  to `state.json` while `run` was already looping could get silently
  reverted the next time `run` had anything else to persist (e.g. a new
  local port allocation) -- found live, on real Wiren Board hardware, as
  `connect` reporting success and the tunnel actually working, but
  `client status` never showing the profile. `sync_once` now reloads
  `profiles` from disk at the start of every cycle instead of trusting
  its own possibly-stale in-memory copy.

### Added

- `.deb` packaging for `frp-jump-client` (amd64/arm64/armhf), self-contained
  under `/opt/frp-jump-client` with its own Python 3.12 -- never touches
  the device's system Python/pip/apt. Built and published automatically
  by the release workflow alongside the PyPI package.
- `client connect`/`disconnect` now wake an already-running `client run`
  immediately instead of waiting out its poll interval (up to 30s by
  default) -- `connect` also waits briefly to show the local port it
  picked, or a clear "not applied yet" message if `run` isn't active.
- `client profiles list`/`profiles delete` -- profiles are persistent
  saved shortcuts now, decoupled from whether the tunnel is currently up:
  `disconnect` only tears down the connection, it no longer deletes the
  profile; `connect <name>` reconnects a saved profile by name alone,
  with no need to retype device/port.

### Changed

- `client connect` takes a single `DEVICE:PORT` argument (e.g. `wb01:22`)
  instead of two separate positional arguments
- `client disconnect` also accepts `DEVICE:PORT` directly (not just a
  saved profile name), for when a profile is missing or was never set
- `connect`'s default profile name (the device's own name) auto-adds the
  port (`wb01-8080`) instead of refusing when you connect to a *second*
  port on the same device without `--as`

## [0.2.0] - 2026-09-26

### Added

- Self-service device/connection management from the CLI, no admin action
  needed beyond a friend's very first device:
  `client add-device` (chain-enroll one more of your own devices),
  `client list` (devices you own), `client delete-device`,
  `client connect`/`client disconnect` (wire yourself up to a port on
  another of your own devices, under a locally-named "profile" — purely
  client-side, never sent to the server)
- Enroll tokens can now defer naming to whoever redeems them
  (`client enroll ... --name`), instead of always fixing the device name
  up front at issue time
- Packaging split: `frp-jump-client` and `frp-jump-server` are now
  separate console-script entry points sharing one package, with the
  heavy server-only dependencies (fastapi, uvicorn, sqlmodel, jinja2,
  python-multipart) moved to an optional `[server]` extra — a device-only
  install (`pip install frp-jump`) no longer pulls them in
- Every CLI command now has full `--help` text with runnable examples

### Removed

- The combined `frp-jump server ...` / `frp-jump client ...` console
  script (`cli/main.py`) — superseded by the dedicated `frp-jump-server`
  and `frp-jump-client` entry points above, and keeping a third,
  role-agnostic one around (that also had to special-case hiding
  `server ...` on a device-only install) was no longer buying anything.
  If you were using it, switch to `frp-jump-server ...` / `frp-jump-client
  ...` directly

### Changed

- The WebUI is now strictly admin-only — the old non-admin "invited user"
  login/dashboard-viewing path is gone, along with `TokenPurpose.INVITE`
  and the email-based invite flow. Onboarding a friend now means the admin
  issues their first enroll token (optionally naming them as its owner via
  the "Add device" form's owner-email field); everything after that is
  self-service via their own CLI
- Server-side `Service` names are now a private, auto-generated
  implementation detail (`svc-<device-id>-<port>`), never shown to or
  typed by a user — the local "profile" name (or the device's own name, by
  default) is what shows up as the `ssh <name>` host alias instead
- Admin dashboard gained Users (with device counts, delete) and Pending
  enroll tokens (with revoke) sections, and an owner + online/offline
  column on the Devices table

### Security

An independent Opus review of the self-service surface above (see
`docs/architecture.md`) found and fixed:

- `delete_user` didn't clean up the target's `Session`/`LoginToken` rows,
  so deleting anyone who had ever logged in or been sent a login link
  raised a raw `IntegrityError` (HTTP 500) instead of succeeding, and a
  leftover unredeemed login link could silently recreate the "deleted"
  account
- `/api/agent/enroll` handed an unvalidated, potentially attacker-supplied
  `requested_name` straight to the CA before validating it, letting a
  malformed name reach a cert-signing operation (and crash it) instead of
  getting a clean 400
- `/api/agent/connect` didn't range-check `target_port`, letting a device
  push a nonsense port (0, negative, >65535) into another owned device's
  frpc config, breaking every tunnel on that device
- `/api/agent/devices/enroll-tokens` echoed registry's real conflict
  reason, letting one owner enumerate another owner's device names — now a
  generic message regardless of cause
- `find_or_create_service` silently ignored a protocol mismatch on reuse,
  so `connect`'s response could claim a protocol the server would not
  actually use, with no error and no working connection
- `/api/agent/connect` allowed connecting to an already-revoked device or
  to the calling device itself, producing grants that look successful but
  never actually work
- `find_or_create_service`/`redeem_enroll_token` could hit a raw
  `IntegrityError` on a service/device-name collision (self-service vs.
  admin-authored, or a concurrent-enroll race) instead of a clean
  `ConflictError`
- `poller.delete_device` interpolated the device name into a URL path
  unescaped
- `sync_ssh_config` could emit two `Host <alias>` blocks for the same
  alias (a `connect --as` name colliding with another grant's device-name
  fallback), making `ssh <alias>` land on an unpredictable target
- `client disconnect` left a local profile stuck forever if the
  server-side connection was already gone (grant revoked, device
  deleted) — it's pruned locally either way now
- `agent_version`'s CLI default was a literal `"0.1.0"` that had already
  drifted from the actual package version; now read from the installed
  package's own metadata

## [0.1.1] - 2026-09-25

### Added

- Device **Delete** (hard, cascades to services/grants, frees the name for
  reuse) alongside the existing **Revoke** (soft, keeps history) — a
  wiped/replaced device can now be re-enrolled under its old name
- CI: the release workflow now also publishes to PyPI (Trusted Publishing
  / OIDC, no stored token) alongside the existing GitHub Release, and
  checks the pushed tag matches `pyproject.toml`'s version before
  building anything

## [0.1.0] - 2026-09-25

First working version: server, device agent, and WebUI, verified end to
end against real `frp` binaries — including a live xtcp hole-punch
timeout falling back to stcp relay, and `ssh <alias>` reaching a real
`sshd` through the tunnel. Deployed for real on the first server the same
day (see the Security section below for what that turned up).

### Added

- `.github/workflows/release.yml`: on a `vX.Y.Z` tag, builds a wheel +
  sdist (`uv build`) and publishes them as a GitHub Release
- `packaging/scripts/frp-jump-login-link`: wrapper around
  `server login-link` for a systemd deployment, so minting a fresh
  login/invite link doesn't require hand-assembling the
  `EnvironmentFile` incantation every time
- README: an explicit "Installing the CLI" section (this isn't
  published to PyPI — install from a tagged release or `git+ssh`), and
  pointers to where the enroll token and login links actually come from

- Private CA (`common/pki.py`) issuing mTLS device certs; a single
  `Settings` source of truth for every port/TTL/version/path
  (`FRP_JUMP_*` env vars + optional TOML config file), nothing hardcoded
  elsewhere (`common/settings.py`)
- `TunnelDriver`/`RelayDriver` abstraction (`driver/base.py`) so the
  tunneling engine is swappable, with a concrete `frp` implementation:
  TOML config rendering (xtcp + stcp wired with `fallbackTo` per grant),
  pinned-release binary download with checksum verification, and
  subprocess supervision (`driver/frp/`)
- Server control-plane: SQLite-backed registry (devices, services,
  grants, users, tokens), passwordless magic-link auth (hashed at rest,
  revocable sessions), and the agent-facing API (enroll / heartbeat /
  desired-state pull) (`server/`)
- WebUI: magic-link login, a dashboard for devices/services/grants,
  forms to add a device (one-time enroll command), add a service, grant
  access, invite another user, and revoke a device or grant —
  server-rendered Jinja2, light/dark aware, no JS framework
- Device agent: enrollment, a sync loop (heartbeat → pull desired-state →
  `driver.apply()`), and automatic `~/.ssh/config` management so
  `ssh <service-name>` works for consumed SSH grants (`agent/`)
- CLI: `frp-jump server init/run/login-link`,
  `frp-jump client enroll/run/status/doctor`
- systemd unit files for both server and client (`packaging/systemd/`)
- Device and grant revocation, enforced at the control-plane
- 180 unit tests (no network) and 2 integration tests (real `frp`
  binaries over loopback), including a negative test proving `frps`
  rejects a client certificate chaining to the wrong CA

### Security

- Every fleet-mutating WebUI route (add device, add service, grant
  access, revoke) now requires `is_admin`
- Device/service names are validated against a strict charset before
  they can reach generated `ssh_config`, `frp` proxy names, or an x509
  CN/SAN — closes an `ssh_config`-injection path
- The agent survives transport-level errors (DNS failure, connection
  refused, timeout) instead of the whole daemon dying on a network blip
- `state.json` (the device's only copy of its private key/cert/API
  token) is written atomically (temp file + fsync + rename)
- Local port allocation uses a dedicated range instead of the kernel's
  ephemeral range, dedups within a sync cycle, and reclaims ports for
  grants that disappear
- SQLite foreign keys are actually enforced (`PRAGMA foreign_keys=ON`);
  private key files are opened with mode `0600` from creation, not
  `chmod`'d after the fact; the session cookie's `Secure` flag now
  accounts for a TLS-terminating reverse proxy; magic-link tokens are
  kept out of the access log (`access_log=False`)
