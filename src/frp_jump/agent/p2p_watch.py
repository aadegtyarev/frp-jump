"""Catch a peer-to-peer tunnel that is open but carries nothing, and send
that one connection through the relay for a while.

frpc's own fallback (``fallbackTo`` / ``fallbackTimeoutMs``, see
``driver/frp/config.py``) only covers a tunnel that fails to *open*. With
``keepTunnelOpen`` a punched QUIC session is reused for every new
connection, and opening a stream on it is a purely local operation -- it
succeeds even when no packet gets through any more (seen behind a
full-tunnel WireGuard VPN: the punch completes, the first stream works,
then the session goes silent). frpc then hands every connection to that
dead session and never falls back, and frpc's background re-punch, at
most every 90s and 8 times an hour, does not notice either.

So the agent checks for itself. Only SSH connections are checked: the SSH
server speaks first, so "connected but no banner within the timeout" is an
unambiguous stall without sending anything into the tunnel. Any other
protocol waits for the client, and there is nothing safe to send it.
"""

from __future__ import annotations

import logging
import socket
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

PROBE_INTERVAL_SECONDS = 60.0
# Longer than frps's own wait for the exposing side's work connection
# (``userConnTimeout``, 10s by default): an exposer frps hasn't noticed is
# gone yet then ends as a close without data, not as a stall.
PROBE_TIMEOUT_SECONDS = 15.0

# How long a stalled connection stays on the relay before peer-to-peer is
# tried again. Doubles on every stall that follows soon after the last
# hold ended, so a network where peer-to-peer never works costs one stall
# window every few hours, not every half hour.
RELAY_HOLD_INITIAL_SECONDS = 30 * 60.0
RELAY_HOLD_MAX_SECONDS = 4 * 3600.0
# Peer-to-peer that has run this long since a hold ended without stalling
# again counts as working: the next stall starts from the initial hold
# (e.g. the laptop moved to a network where punching works).
RELAY_HOLD_RESET_AFTER_SECONDS = 3600.0


def probe_banner(port: int, *, timeout: float = PROBE_TIMEOUT_SECONDS) -> bool | None:
    """Connect to ``127.0.0.1:port`` and wait for the first byte.

    True: something answered. False: the connection opened but stayed
    silent for ``timeout`` -- the stall this module exists for. None:
    anything else (nothing listening, connection closed or reset with no
    data), which points at frpc or the far side, not at the tunnel, so it
    is not a reason to change how the connection is routed."""
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    except OSError:
        return None
    with sock:
        try:
            return bool(sock.recv(1)) or None
        except TimeoutError:
            return False
        except OSError:
            return None


class P2PWatch:
    """Per-connection relay holds, kept in memory only: a restarted agent
    starts every connection on peer-to-peer again, which is the right
    default after whatever made someone restart it."""

    def __init__(
        self,
        *,
        probe: Callable[[int], bool | None] = probe_banner,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._probe = probe
        self._clock = clock
        # Not right away: the first cycle has just started or reloaded
        # frpc, and a probe then measures the startup, not the tunnel.
        self._next_probe_at = clock() + PROBE_INTERVAL_SECONDS
        # grant_id -> when its relay hold ends
        self._held_until: dict[str, float] = {}
        # grant_id -> (when the last hold ended, how long it was)
        self._last_hold: dict[str, tuple[float, float]] = {}

    def relayed(self) -> frozenset[str]:
        """Grants that must go through the relay right now."""
        now = self._clock()
        for grant_id, until in list(self._held_until.items()):
            if until <= now:
                del self._held_until[grant_id]
                logger.info("retrying peer-to-peer for connection %s", grant_id)
        return frozenset(self._held_until)

    def check(self, ssh_grants: Iterable[tuple[str, int]]) -> bool:
        """Probe every SSH grant still on peer-to-peer, at most once per
        ``PROBE_INTERVAL_SECONDS``. ``ssh_grants`` is (grant_id, local
        port). Returns whether any grant was moved to the relay."""
        now = self._clock()
        if now < self._next_probe_at:
            return False
        self._next_probe_at = now + PROBE_INTERVAL_SECONDS

        held = self.relayed()
        targets = [(g, port) for g, port in ssh_grants if g not in held]
        if not targets:
            return False
        with ThreadPoolExecutor(max_workers=len(targets)) as pool:
            results = list(pool.map(lambda t: self._probe(t[1]), targets))

        moved = False
        for (grant_id, port), result in zip(targets, results, strict=True):
            if result is False:
                hold = self._hold_length(grant_id, now)
                self._held_until[grant_id] = now + hold
                self._last_hold[grant_id] = (now + hold, hold)
                logger.warning(
                    "peer-to-peer tunnel on port %d is open but silent, using the "
                    "relay for %.0f min",
                    port,
                    hold / 60,
                )
                moved = True
        return moved

    def _hold_length(self, grant_id: str, now: float) -> float:
        last = self._last_hold.get(grant_id)
        if last is None:
            return RELAY_HOLD_INITIAL_SECONDS
        ended_at, length = last
        if now - ended_at > RELAY_HOLD_RESET_AFTER_SECONDS:
            return RELAY_HOLD_INITIAL_SECONDS
        return min(length * 2, RELAY_HOLD_MAX_SECONDS)
