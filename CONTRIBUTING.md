# Contributing

This started as a personal tool, but issues and PRs are welcome.

## Setup

```sh
uv sync
```

Requires Python 3.12+. Everything else (Typer, FastAPI, SQLModel,
`cryptography`, ...) is pinned in `pyproject.toml`/`uv.lock`.

## Running things locally

```sh
uv run pytest tests/unit -q          # fast, no network, run this before every commit
uv run ruff check .                  # lint; there's no separate formatter step
uv run pytest tests/integration -m integration -q   # downloads real frp binaries, loopback only
uv run frp-jump --help
```

There's no CI configured yet — run the two commands above locally before
opening a PR.

## Conventions this codebase follows

- **No hardcoded configuration.** Every port, TTL, version pin, or path
  that could reasonably differ per deployment lives in
  `common/settings.py` and flows in through function/constructor
  parameters, not module-level constants read deep in the call stack.
  See that file's docstring.
- **The tunneling engine is behind an abstraction.** `driver/base.py`'s
  `TunnelDriver`/`RelayDriver` Protocols are what the rest of the
  codebase talks to; `driver/frp/` is the only place that knows it's
  `frp` under the hood. Keep it that way if you touch the driver layer.
- **`registry.py` stays framework-agnostic.** It takes a plain SQLModel
  `Session`, never a FastAPI `Request` — that's what makes it unit
  -testable without spinning up the app, and reusable by both
  `server/api.py` and `server/web.py`.
- **Views are dataclasses, not ORM rows,** when data crosses a boundary
  (API response, template context) — see `registry.ExposedGrantView`
  /`ConsumedGrantView`/`ServiceView`/`GrantView`. Keeps the DB schema
  free to change without rippling into templates/JSON shapes.
- **Comments explain *why*, not *what.*** A non-obvious constraint, a
  workaround for a specific upstream behavior, a subtlety that would
  surprise a reader — yes. A restatement of the code — no.
- **Every module change gets a test alongside it.** `tests/unit/` mirrors
  `src/frp_jump/` roughly 1:1. Network-touching tests go in
  `tests/integration/` behind the `integration` marker (excluded by
  default; see `pyproject.toml`'s `addopts`).
- Anything touching certs, tokens, or the agent's local port
  allocation has probably already surprised someone once — check
  [`docs/architecture.md`](docs/architecture.md)'s "gotchas" section
  before re-deriving it from scratch.

## Commit messages

Imperative mood, explain the *why* when it's not obvious from the diff
("Fix X" is fine when X is self-explanatory; "Switch to write-temp+rename
for state.json — truncate-then-write could brick a device on power loss
mid-write" is better when it isn't).

## Reporting a security issue

There's no dedicated security contact for a project this size — open an
issue, or if it's something you'd rather not post publicly, reach the
maintainer directly first.
