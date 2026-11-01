"""detect_kind against fake filesystem trees: never the real /proc or /sys."""

from pathlib import Path

import pytest

from frp_jump.agent import device_kind
from frp_jump.agent.device_kind import detect_kind
from frp_jump.common.device_display import DeviceIcon

_X86_HOST_CPUINFO = "processor\t: 0\nflags\t\t: fpu vme de pse tsc msr sse sse2 lm\n"
_X86_GUEST_CPUINFO = "processor\t: 0\nflags\t\t: fpu vme de pse tsc hypervisor lm\n"
_ARM_CPUINFO = "processor\t: 0\nFeatures\t: fp asimd evtstrm crc32 cpuid\n"


def _write(root: Path, rel: str, content: str | bytes) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content)


def _chassis(root: Path, value: int | str) -> None:
    _write(root, "sys/class/dmi/id/chassis_type", f"{value}\n")


def _battery(root: Path, name: str, *, scope: str | None = None, kind: str = "Battery") -> None:
    _write(root, f"sys/class/power_supply/{name}/type", f"{kind}\n")
    if scope is not None:
        _write(root, f"sys/class/power_supply/{name}/scope", f"{scope}\n")


def _device_tree(root: Path, model: str) -> None:
    _write(root, "proc/device-tree/model", model.encode() + b"\x00")


def test_empty_root_is_linux(tmp_path) -> None:
    assert detect_kind(tmp_path) is DeviceIcon.LINUX


def test_missing_root_is_linux(tmp_path) -> None:
    assert detect_kind(tmp_path / "nope") is DeviceIcon.LINUX


def test_wiren_board(tmp_path) -> None:
    _write(tmp_path, "etc/wb-release", "SUITE=stable\n")
    _device_tree(tmp_path, "Wiren Board rev. 7.4.2 (i.MX6ULL)")
    _write(tmp_path, "proc/cpuinfo", _ARM_CPUINFO)
    assert detect_kind(tmp_path) is DeviceIcon.WIRENBOARD


def test_wiren_board_wins_over_everything_else(tmp_path) -> None:
    _write(tmp_path, "etc/wb-release", "")
    _write(tmp_path, "etc/openwrt_release", "")
    _write(tmp_path, "proc/cpuinfo", _X86_GUEST_CPUINFO)
    assert detect_kind(tmp_path) is DeviceIcon.WIRENBOARD


def test_openwrt(tmp_path) -> None:
    _write(tmp_path, "etc/openwrt_release", "DISTRIB_ID='OpenWrt'\n")
    _device_tree(tmp_path, "GL.iNet GL-MT300N-V2")
    assert detect_kind(tmp_path) is DeviceIcon.ROUTER


def test_vm_by_cpuinfo_flag(tmp_path) -> None:
    _write(tmp_path, "proc/cpuinfo", _X86_GUEST_CPUINFO)
    _chassis(tmp_path, 1)
    assert detect_kind(tmp_path) is DeviceIcon.LINUX


def test_hyperv_desktop_chassis_is_still_a_vm(tmp_path) -> None:
    """Hyper-V reports chassis 3 (Desktop); the VM rule must come first."""
    _write(tmp_path, "proc/cpuinfo", _X86_GUEST_CPUINFO)
    _chassis(tmp_path, 3)
    assert detect_kind(tmp_path) is DeviceIcon.LINUX


def test_vm_by_sys_hypervisor_type(tmp_path) -> None:
    _write(tmp_path, "proc/cpuinfo", _X86_HOST_CPUINFO)
    _write(tmp_path, "sys/hypervisor/type", "xen\n")
    _chassis(tmp_path, 23)
    assert detect_kind(tmp_path) is DeviceIcon.LINUX


def test_empty_sys_hypervisor_type_is_not_a_vm(tmp_path) -> None:
    _write(tmp_path, "proc/cpuinfo", _X86_HOST_CPUINFO)
    _write(tmp_path, "sys/hypervisor/type", "\n")
    _chassis(tmp_path, 3)
    assert detect_kind(tmp_path) is DeviceIcon.PC


def test_hypervisor_word_outside_flags_does_not_count(tmp_path) -> None:
    _write(tmp_path, "proc/cpuinfo", "model name\t: hypervisor-ready cpu\n" + _X86_HOST_CPUINFO)
    _chassis(tmp_path, 3)
    assert detect_kind(tmp_path) is DeviceIcon.PC


@pytest.mark.parametrize(
    ("chassis", "expected"),
    [
        *[(c, DeviceIcon.LAPTOP) for c in (8, 9, 10, 14, 30, 31, 32)],
        *[(c, DeviceIcon.SERVER) for c in (17, 23, 25, 28, 29)],
        *[(c, DeviceIcon.PC) for c in (3, 4, 5, 6, 7, 13, 15, 16, 24, 35, 36)],
        *[(c, DeviceIcon.SBC) for c in (33, 34)],
        *[(c, DeviceIcon.LINUX) for c in (1, 2, 11, 99)],
    ],
)
def test_chassis_types_on_bare_metal(tmp_path, chassis, expected) -> None:
    _write(tmp_path, "proc/cpuinfo", _X86_HOST_CPUINFO)
    _chassis(tmp_path, chassis)
    assert detect_kind(tmp_path) is expected


def test_chassis_wins_over_battery(tmp_path) -> None:
    _chassis(tmp_path, 3)
    _battery(tmp_path, "BAT0")
    assert detect_kind(tmp_path) is DeviceIcon.PC


@pytest.mark.parametrize("chassis", [1, 2, 11, 99, "garbage"])
def test_unhelpful_chassis_with_a_battery_without_scope_is_a_laptop(tmp_path, chassis) -> None:
    _chassis(tmp_path, chassis)
    _battery(tmp_path, "AC", kind="Mains")
    _battery(tmp_path, "BAT0")
    assert detect_kind(tmp_path) is DeviceIcon.LAPTOP


def test_unhelpful_chassis_with_a_system_scope_battery_is_a_laptop(tmp_path) -> None:
    _chassis(tmp_path, 2)
    _battery(tmp_path, "BAT0", scope="System")
    assert detect_kind(tmp_path) is DeviceIcon.LAPTOP


def test_unhelpful_chassis_with_only_a_peripheral_battery_is_linux(tmp_path) -> None:
    """A mouse, headset or USB UPS battery says nothing about the host."""
    _chassis(tmp_path, 1)
    _battery(tmp_path, "hidpp_battery_0", scope="Device")
    _battery(tmp_path, "AC", kind="Mains")
    assert detect_kind(tmp_path) is DeviceIcon.LINUX


def test_unhelpful_chassis_without_any_battery_is_linux(tmp_path) -> None:
    _chassis(tmp_path, 11)
    _battery(tmp_path, "AC", kind="Mains")
    assert detect_kind(tmp_path) is DeviceIcon.LINUX


def test_device_tree_without_dmi_is_sbc(tmp_path) -> None:
    _write(tmp_path, "proc/cpuinfo", _ARM_CPUINFO)
    _device_tree(tmp_path, "Raspberry Pi 4 Model B Rev 1.4")
    assert detect_kind(tmp_path) is DeviceIcon.SBC


def test_pi_with_a_ups_battery_is_still_sbc(tmp_path) -> None:
    """Without DMI the battery check does not run."""
    _write(tmp_path, "proc/cpuinfo", _ARM_CPUINFO)
    _device_tree(tmp_path, "Raspberry Pi 4 Model B Rev 1.4")
    _battery(tmp_path, "max17040_battery")
    assert detect_kind(tmp_path) is DeviceIcon.SBC


def test_wiren_board_device_tree_without_wb_release_is_sbc(tmp_path) -> None:
    """Only etc/wb-release makes a Wiren Board; its device tree alone is an sbc."""
    _device_tree(tmp_path, "Wiren Board rev. 7.4.2 (i.MX6ULL)")
    assert detect_kind(tmp_path) is DeviceIcon.SBC


def test_arm_qemu_virt_without_hypervisor_flag_comes_out_as_sbc(tmp_path) -> None:
    """Known caveat from the plan: the owner overrides it on the server."""
    _write(tmp_path, "proc/cpuinfo", _ARM_CPUINFO)
    _device_tree(tmp_path, "linux,dummy-virt")
    assert detect_kind(tmp_path) is DeviceIcon.SBC


def test_dmi_wins_over_device_tree(tmp_path) -> None:
    _chassis(tmp_path, 9)
    _device_tree(tmp_path, "Some ARM laptop")
    assert detect_kind(tmp_path) is DeviceIcon.LAPTOP


def test_empty_device_tree_model_is_linux(tmp_path) -> None:
    _write(tmp_path, "proc/device-tree/model", b"\x00")
    assert detect_kind(tmp_path) is DeviceIcon.LINUX


def test_battery_without_dmi_and_without_device_tree_is_linux(tmp_path) -> None:
    _battery(tmp_path, "BAT0")
    assert detect_kind(tmp_path) is DeviceIcon.LINUX


# --- unreadable files: any read error means "this rule does not match" ---


def test_unreadable_cpuinfo_and_chassis_fall_through(tmp_path) -> None:
    # A directory where a file is expected raises IsADirectoryError on read,
    # which works the same when the tests run as root (unlike chmod 000).
    (tmp_path / "proc/cpuinfo").mkdir(parents=True)
    (tmp_path / "sys/hypervisor/type").mkdir(parents=True)
    (tmp_path / "sys/class/dmi/id/chassis_type").mkdir(parents=True)
    _device_tree(tmp_path, "Raspberry Pi 4 Model B Rev 1.4")
    assert detect_kind(tmp_path) is DeviceIcon.SBC


def test_unreadable_device_tree_model_is_linux(tmp_path) -> None:
    (tmp_path / "proc/device-tree/model").mkdir(parents=True)
    assert detect_kind(tmp_path) is DeviceIcon.LINUX


def test_power_supply_not_a_directory_is_no_battery(tmp_path) -> None:
    _chassis(tmp_path, 2)
    _write(tmp_path, "sys/class/power_supply", "not a directory")
    assert detect_kind(tmp_path) is DeviceIcon.LINUX


def test_unreadable_battery_type_is_skipped(tmp_path) -> None:
    _chassis(tmp_path, 2)
    (tmp_path / "sys/class/power_supply/BAT0/type").mkdir(parents=True)
    assert detect_kind(tmp_path) is DeviceIcon.LINUX


def test_invalid_utf8_does_not_raise(tmp_path) -> None:
    _write(tmp_path, "proc/cpuinfo", b"\xff\xfe flags : \xff\n")
    _write(tmp_path, "sys/class/dmi/id/chassis_type", b"\xff\xff")
    assert detect_kind(tmp_path) is DeviceIcon.LINUX


def test_permission_errors_fall_through(tmp_path, monkeypatch) -> None:
    _write(tmp_path, "etc/wb-release", "")
    _chassis(tmp_path, 9)

    def denied(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "read_text", denied)
    monkeypatch.setattr(Path, "exists", denied)
    monkeypatch.setattr(Path, "iterdir", denied)
    assert detect_kind(tmp_path) is DeviceIcon.LINUX


def test_an_unexpected_error_falls_back_to_linux(tmp_path, monkeypatch) -> None:
    def boom(root):
        raise RuntimeError("bug")

    monkeypatch.setattr(device_kind, "_detect", boom)
    assert detect_kind(tmp_path) is DeviceIcon.LINUX
