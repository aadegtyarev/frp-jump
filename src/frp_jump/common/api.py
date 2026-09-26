"""The agent-facing API's URL prefix -- shared between `server/app.py`
(which mounts it) and `agent/poller.py`/`agent/enroll.py` (which build
request URLs against it), so the two can never drift apart.

Not a ``Settings`` field: it's an internal wire-format detail of this
codebase talking to itself, not something a deployment would ever want to
change independently on one side. Lives in ``common/`` rather than
`server/api.py` so the lean device-only install (no fastapi/sqlmodel) can
still import it.
"""

from __future__ import annotations

AGENT_API_PREFIX = "/api/agent"

#: The wire format this codebase speaks -- request/response shapes, field
#: meanings, what a device is expected to do with what it's told. Bumped
#: only when that changes in a way an older client/server can't safely
#: handle; NOT the same as the package version, which also changes for
#: things that don't touch the wire at all (a new CLI flag, a bugfix in
#: unrelated code). A client compares this against what the server
#: reports (``DesiredStateResponse.protocol_version`` / ``GET
#: /api/agent/version``) on every poll cycle -- see
#: ``agent/poller.py``'s ``ProtocolMismatchError``: a mismatch stops that
#: cycle from *applying* anything (an unknown wire shape is a correctness
#: risk to guess through), but never tears down whatever tunnel is
#: already running, and the daemon keeps polling/retrying rather than
#: exiting -- one side updates lands them back in sync on its own.
PROTOCOL_VERSION = 1
