# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/); versions will
follow [SemVer](https://semver.org/) once something is tagged/released.

## [Unreleased]

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
