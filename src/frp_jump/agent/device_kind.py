"""Detect what kind of machine the agent runs on, for the device icon.

``detect_kind`` reads a handful of small files under ``root`` (``/`` in
production, a fake tree in tests), starts no subprocess and never raises:
any read error means "this rule does not match". The first matching rule
wins:

1. ``etc/wb-release`` -> Wiren Board.
2. ``etc/openwrt_release`` -> router.
3. A virtual machine -> linux. Checked before DMI because Hyper-V reports
   chassis type 3, "Desktop".
4. DMI present: the SMBIOS chassis type decides; an unhelpful type falls
   through to the battery check (a host battery -> laptop, else linux).
5. No DMI, but a device-tree model -> single-board computer.
6. Otherwise linux.

The result is only a default: the owner's icon override on the server
always wins, so a wrong guess (an ARM QEMU ``virt`` guest coming out as
``sbc``, say) costs one ``devices icon`` call.
"""

from __future__ import annotations

import logging
from pathlib import Path

from frp_jump.common.device_display import DeviceIcon

logger = logging.getLogger(__name__)

_LAPTOP_CHASSIS = frozenset({8, 9, 10, 14, 30, 31, 32})
_SERVER_CHASSIS = frozenset({17, 23, 25, 28, 29})
_PC_CHASSIS = frozenset({3, 4, 5, 6, 7, 13, 15, 16, 24, 35, 36})
_SBC_CHASSIS = frozenset({33, 34})


def _read(path: Path) -> str | None:
    """The file's text, or None if it is missing or unreadable for any reason."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return None


def _exists(path: Path) -> bool:
    try:
        return path.exists()
    except (OSError, ValueError):
        return False


def _is_vm(root: Path) -> bool:
    cpuinfo = _read(root / "proc/cpuinfo") or ""
    for line in cpuinfo.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip() == "flags" and "hypervisor" in value.split():
            return True
    hypervisor_type = _read(root / "sys/hypervisor/type")
    return bool(hypervisor_type and hypervisor_type.strip())


def _has_host_battery(root: Path) -> bool:
    """A power supply of type Battery that is not a peripheral's (scope=Device).

    A missing ``scope`` file counts as a host battery: ACPI laptop
    batteries usually have none.
    """
    try:
        supplies = sorted((root / "sys/class/power_supply").iterdir())
    except (OSError, ValueError):
        return False
    for supply in supplies:
        if (_read(supply / "type") or "").strip() != "Battery":
            continue
        if (_read(supply / "scope") or "").strip() != "Device":
            return True
    return False


def _from_dmi(root: Path, chassis_text: str) -> DeviceIcon:
    try:
        chassis = int(chassis_text.strip())
    except ValueError:
        chassis = None
    if chassis in _LAPTOP_CHASSIS:
        return DeviceIcon.LAPTOP
    if chassis in _SERVER_CHASSIS:
        return DeviceIcon.SERVER
    if chassis in _PC_CHASSIS:
        return DeviceIcon.PC
    if chassis in _SBC_CHASSIS:
        return DeviceIcon.SBC
    # 11 (hand held), 1 (other), 2 (unknown), anything else.
    return DeviceIcon.LAPTOP if _has_host_battery(root) else DeviceIcon.LINUX


def _detect(root: Path) -> DeviceIcon:
    if _exists(root / "etc/wb-release"):
        return DeviceIcon.WIRENBOARD
    if _exists(root / "etc/openwrt_release"):
        return DeviceIcon.ROUTER
    if _is_vm(root):
        return DeviceIcon.LINUX
    chassis_text = _read(root / "sys/class/dmi/id/chassis_type")
    if chassis_text is not None:
        return _from_dmi(root, chassis_text)
    # The battery check deliberately does not run without DMI: an ARM
    # board with a fuel gauge (or a UPS hat) is still an sbc.
    model = _read(root / "proc/device-tree/model")
    if model and model.strip("\x00 \t\r\n"):
        return DeviceIcon.SBC
    return DeviceIcon.LINUX


def detect_kind(root: Path = Path("/")) -> DeviceIcon:
    """The detected device kind; ``linux`` when nothing more specific matches.

    Never raises: the kind is cosmetic and must not stop the agent.
    """
    try:
        return _detect(root)
    except Exception:
        logger.warning("device kind detection failed, reporting linux", exc_info=True)
        return DeviceIcon.LINUX
