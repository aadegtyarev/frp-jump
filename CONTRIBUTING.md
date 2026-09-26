# Contributing

This started as a personal tool. Issues and pull requests are welcome.

## Setup

```sh
uv sync
```

Python 3.12 or newer. Everything else is pinned in `pyproject.toml` and
`uv.lock`.

## Running things

```sh
uv run pytest tests/unit -q       # fast, no network — run before every commit
uv run ruff check .               # lint; there is no separate formatter step
uv run frp-jump-client --help
uv run frp-jump-server --help
```

The integration suite downloads real frp binaries and runs them over loopback:

```sh
uv run pytest tests/integration -m integration -q
```

It proves the whole chain — real binaries, real mTLS, a real hole-punch timeout
followed by a real relay fallback. It cannot prove NAT traversal between two
separate networks. Check that by hand on real devices.

There is no CI on pull requests yet, only on tag push to build and publish a
release. Run the unit tests and the linter locally before opening one.

## Conventions

Design rules — the driver abstraction, keeping `registry.py` framework-agnostic,
where configuration lives — are in
[docs/architecture.md](docs/architecture.md#the-four-rules-this-codebase-follows).
Read that before a change that touches the driver layer, certificates, tokens,
or the agent's port allocation. The gotchas section there exists because each
item in it already surprised someone once.

Two things about the writing itself:

**Comments explain why, not what.** A non-obvious constraint, a workaround for
specific upstream behaviour, something that would surprise a reader — yes. A
restatement of the line below it — no.

**Every module change gets a test alongside it.** `tests/unit/` mirrors
`src/frp_jump/` roughly one to one. Anything that touches the network goes in
`tests/integration/` behind the `integration` marker, which is excluded by
default.

## Commit messages

Imperative mood. Explain the why when the diff doesn't.

> Fix the port allocation off-by-one

is fine when it speaks for itself.

> Switch state.json to write-temp-then-rename — truncate-then-write could brick
> a device on power loss mid-write

is better when it doesn't.

## Documentation

Docs live in [`docs/`](docs/), organised by what the reader is trying to do:
learn, look something up, understand, or fix something. A change that alters
behaviour should update the page that covers it. `README.md` is the front door
and stays short.

## Reporting a security issue

There is no dedicated security contact for a project this size. Open an issue,
or reach the maintainer directly if you'd rather not post it publicly. See
[docs/security.md](docs/security.md) for the model and its known weak spots.
