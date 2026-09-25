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
