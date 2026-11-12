import socket
import threading

from frp_jump.agent import p2p_watch
from frp_jump.agent.p2p_watch import P2PWatch, probe_banner


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _watch(results: dict[int, bool | None]) -> tuple[P2PWatch, Clock, list[int]]:
    clock = Clock()
    probed: list[int] = []

    def probe(port: int) -> bool | None:
        probed.append(port)
        return results[port]

    return P2PWatch(probe=probe, clock=clock), clock, probed


def test_a_silent_tunnel_goes_to_the_relay_and_comes_back_after_the_hold() -> None:
    watch, clock, _ = _watch({40000: False, 40001: True})

    assert watch.check([("g1", 40000), ("g2", 40001)]) is True
    assert watch.relayed() == {"g1"}

    clock.now += p2p_watch.RELAY_HOLD_INITIAL_SECONDS
    assert watch.relayed() == frozenset()


def test_an_answering_or_unreachable_tunnel_stays_on_peer_to_peer() -> None:
    """None (nothing listening, closed without data) points at frpc or the
    far side, not at a stalled tunnel -- the relay would not help."""
    watch, _, _ = _watch({40000: True, 40001: None})

    assert watch.check([("g1", 40000), ("g2", 40001)]) is False
    assert watch.relayed() == frozenset()


def test_probes_run_at_most_once_per_interval_and_skip_held_grants() -> None:
    watch, clock, probed = _watch({40000: False, 40001: True})

    watch.check([("g1", 40000), ("g2", 40001)])
    watch.check([("g1", 40000), ("g2", 40001)])
    assert sorted(probed) == [40000, 40001]

    clock.now += p2p_watch.PROBE_INTERVAL_SECONDS
    watch.check([("g1", 40000), ("g2", 40001)])
    assert sorted(probed) == [40000, 40001, 40001]


def test_the_hold_doubles_on_a_repeat_stall_and_resets_after_a_quiet_hour() -> None:
    watch, clock, _ = _watch({40000: False})
    initial = p2p_watch.RELAY_HOLD_INITIAL_SECONDS

    def stall_and_measure() -> float:
        start = clock.now
        watch.check([("g1", 40000)])
        held_until = watch._held_until["g1"]
        clock.now = held_until  # hold ends
        assert watch.relayed() == frozenset()
        clock.now += p2p_watch.PROBE_INTERVAL_SECONDS
        return held_until - start

    assert stall_and_measure() == initial
    assert stall_and_measure() == initial * 2
    for _ in range(5):
        stall_and_measure()
    assert watch._last_hold["g1"][1] == p2p_watch.RELAY_HOLD_MAX_SECONDS

    clock.now += p2p_watch.RELAY_HOLD_RESET_AFTER_SECONDS
    assert stall_and_measure() == initial


def _server(behaviour) -> tuple[socket.socket, int]:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]

    def serve() -> None:
        conn, _ = srv.accept()
        behaviour(conn)

    threading.Thread(target=serve, daemon=True).start()
    return srv, port


def test_probe_banner_reads_a_banner() -> None:
    srv, port = _server(lambda c: (c.sendall(b"SSH-2.0-test\r\n"), c.close()))
    with srv:
        assert probe_banner(port, timeout=2) is True


def test_probe_banner_reports_a_silent_connection_as_stalled() -> None:
    held = []
    srv, port = _server(held.append)
    with srv:
        assert probe_banner(port, timeout=0.3) is False


def test_probe_banner_ignores_a_close_without_data_and_a_closed_port() -> None:
    srv, port = _server(lambda c: c.close())
    with srv:
        assert probe_banner(port, timeout=2) is None

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        free = s.getsockname()[1]
    assert probe_banner(free, timeout=1) is None
