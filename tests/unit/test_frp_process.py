import shutil
import time

import pytest

from frp_jump.driver.frp.process import ProcessSupervisor, SubprocessSupervisor

pytestmark = pytest.mark.skipif(shutil.which("sleep") is None, reason="needs /bin/sleep")


def test_subprocess_supervisor_satisfies_protocol() -> None:
    assert isinstance(SubprocessSupervisor(), ProcessSupervisor)


def test_is_running_false_before_start() -> None:
    supervisor = SubprocessSupervisor()
    assert supervisor.is_running() is False


def test_start_makes_is_running_true() -> None:
    supervisor = SubprocessSupervisor()
    supervisor.start(["sleep", "5"])
    try:
        assert supervisor.is_running() is True
    finally:
        supervisor.stop()


def test_stop_makes_is_running_false() -> None:
    supervisor = SubprocessSupervisor()
    supervisor.start(["sleep", "5"])
    supervisor.stop()
    assert supervisor.is_running() is False


def test_start_again_replaces_the_running_process() -> None:
    supervisor = SubprocessSupervisor()
    supervisor.start(["sleep", "5"])
    first_pid = supervisor._proc.pid  # noqa: SLF001 - white-box check
    supervisor.start(["sleep", "5"])
    try:
        second_pid = supervisor._proc.pid  # noqa: SLF001
        assert second_pid != first_pid
        assert supervisor.is_running() is True
    finally:
        supervisor.stop()


def test_is_running_false_after_process_exits_on_its_own() -> None:
    supervisor = SubprocessSupervisor()
    supervisor.start(["sleep", "0.1"])
    time.sleep(0.3)
    assert supervisor.is_running() is False


def test_stop_is_a_noop_when_nothing_is_running() -> None:
    supervisor = SubprocessSupervisor()
    supervisor.stop()  # must not raise
    assert supervisor.is_running() is False
