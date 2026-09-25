# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/); versions will
follow [SemVer](https://semver.org/) once something is tagged/released.

## [Unreleased]

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
