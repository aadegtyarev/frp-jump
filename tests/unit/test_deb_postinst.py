"""packaging/deb/postinst, run under /bin/sh with stubbed dpkg-query/systemctl.

The script's paths are rooted at $DPKG_ROOT (empty on a real install), so the
site-packages it cleans lives under tmp_path here.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

POSTINST = Path(__file__).resolve().parents[2] / "packaging" / "deb" / "postinst"
SITE = "/opt/frp-jump-client/site-packages"
OWNED_DIST_INFO = ["frp_jump-0.3.19.dist-info", "httpx-0.28.1.dist-info"]
STALE_DIST_INFO = ["frp_jump-0.3.15.dev0.dist-info", "httpx-0.27.0.dist-info"]


def _stub(bin_dir: Path, name: str, body: str) -> None:
    path = bin_dir / name
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)


@pytest.fixture
def env(tmp_path):
    """A minimal PATH (only the externals the script uses, plus stubs) so a
    real deb-systemd-invoke/systemctl on the test machine is never reached."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("cat", "grep", "rm"):
        (bin_dir / tool).symlink_to(shutil.which(tool))
    calls = tmp_path / "calls.log"
    owned = tmp_path / "owned.txt"
    owned.write_text("".join(f"{SITE}/{d}\n" for d in ["", *OWNED_DIST_INFO]))
    _stub(bin_dir, "dpkg-query", f'cat "{owned}"')
    for tool in ("systemctl", "deb-systemd-invoke"):
        _stub(bin_dir, tool, f'echo "{tool} $*" >> "{calls}"')

    root = tmp_path / "root"
    site = root / SITE.lstrip("/")
    for name in OWNED_DIST_INFO + STALE_DIST_INFO:
        (site / name).mkdir(parents=True)
        (site / name / "METADATA").write_text("Metadata-Version: 2.4\n")
    (site / "frp_jump").mkdir()

    return {
        "bin": bin_dir,
        "calls": calls,
        "owned": owned,
        "site": site,
        "vars": {"PATH": str(bin_dir), "DPKG_ROOT": str(root)},
    }


def _run(env, *args):
    result = subprocess.run(
        ["/bin/sh", str(POSTINST), *args],
        env={**os.environ, **env["vars"]},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return env["calls"].read_text().splitlines() if env["calls"].exists() else []


def test_upgrade_removes_only_unowned_dist_info(env):
    _run(env, "configure", "0.3.18")

    remaining = sorted(p.name for p in env["site"].iterdir())
    assert remaining == sorted([*OWNED_DIST_INFO, "frp_jump"])


@pytest.mark.parametrize("dpkg_query", ["exit 1", "true"], ids=["fails", "empty"])
def test_no_ownership_list_keeps_everything(env, dpkg_query):
    _stub(env["bin"], "dpkg-query", dpkg_query)

    _run(env, "configure", "0.3.18")

    assert len(list(env["site"].iterdir())) == len(OWNED_DIST_INFO + STALE_DIST_INFO) + 1


def test_upgrade_try_restarts_the_system_unit(env):
    calls = _run(env, "configure", "0.3.18")

    assert calls == [
        "systemctl daemon-reload",
        "deb-systemd-invoke try-restart frp-jump-client.service",
    ]


def test_fresh_install_does_not_touch_the_service(env):
    calls = _run(env, "configure", "")

    assert calls == ["systemctl daemon-reload"]


def test_without_deb_systemd_invoke_falls_back_to_systemctl(env):
    (env["bin"] / "deb-systemd-invoke").unlink()

    calls = _run(env, "configure", "0.3.18")

    assert calls[-1] == "systemctl try-restart frp-jump-client.service"


def test_failed_restart_does_not_fail_the_upgrade(env):
    _stub(env["bin"], "deb-systemd-invoke", "exit 1")

    _run(env, "configure", "0.3.18")
