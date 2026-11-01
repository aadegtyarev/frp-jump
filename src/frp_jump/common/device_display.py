"""The built-in device icon set, shared by the server and the clients.

Lives in ``common/`` with no sqlmodel import, so the lean client install
can use it too. Values are lowercase ASCII and go on the wire as is.
Adding a value later is backward compatible: an older server ignores an
unknown ``kind`` in a heartbeat, an older client shows its generic glyph.

``auto`` is not a member: it is a CLI word for "drop the override" and is
never stored or sent.
"""

from __future__ import annotations

from enum import StrEnum

#: The ``GET /version`` feature flag for device labels and icons: the
#: ``/devices`` fields, the ``/display`` route and ``kind`` in heartbeat.
FEATURE_DEVICE_DISPLAY = "device-display"


class DeviceIcon(StrEnum):
    LINUX = "linux"
    WIRENBOARD = "wirenboard"
    SERVER = "server"
    PC = "pc"
    LAPTOP = "laptop"
    ROUTER = "router"
    SBC = "sbc"
    CAMERA = "camera"
    HOME = "home"
    PHONE = "phone"
