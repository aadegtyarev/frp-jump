"""Download and verify the pinned frp release for the host architecture.

Trust model: binaries are fetched over HTTPS straight from the official
``fatedier/frp`` GitHub release, and checked against the sha256 digest the
same release publishes in ``frp_sha256_checksums.txt``. Since both files
come from the same connection/host, this only guards against a
corrupted/truncated download -- it is NOT an independent integrity check
against a compromised connection or a compromised upstream release (an
attacker who can tamper with one response can tamper with both). A
stronger guarantee would mean pinning the expected per-arch digests next
to ``frp_version`` in settings.py instead of trusting a file fetched at
install time; not done here -- acceptable for this project's threat model
(see docs/security.md), but worth revisiting if that changes.
"""

from __future__ import annotations

import hashlib
import platform
import shutil
import stat
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

import httpx

_CHECKSUMS_ASSET = "frp_sha256_checksums.txt"


class UnsupportedArchitecture(RuntimeError):
    pass


class ChecksumMismatch(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class FrpBinaries:
    frpc: Path
    frps: Path


def frp_arch(machine: str | None = None) -> str:
    """Map ``platform.machine()`` to frp's release arch suffix."""
    machine = (machine if machine is not None else platform.machine()).lower()
    if machine in {"x86_64", "amd64"}:
        return "amd64"
    if machine in {"aarch64", "arm64"}:
        return "arm64"
    if machine.startswith("armv7"):
        # Debian armhf (Wiren Board's ARM controllers) is hard-float ARMv7.
        return "arm_hf"
    if machine.startswith("arm"):
        return "arm"
    raise UnsupportedArchitecture(f"no frp release known for machine {machine!r}")


def asset_name(arch: str, *, version: str) -> str:
    return f"frp_{version}_linux_{arch}.tar.gz"


def release_url(version: str) -> str:
    return f"https://github.com/fatedier/frp/releases/download/v{version}"


def parse_checksums(text: str) -> dict[str, str]:
    """Parse a ``sha256sum``-style checksums file into {filename: hex digest}."""
    result: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        digest, sep, name = line.partition("  ")
        if not sep:
            digest, sep, name = line.partition(" *")
        if not sep:
            continue
        result[name.strip()] = digest.strip()
    return result


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_installed(
    install_dir: Path,
    *,
    version: str,
    machine: str | None = None,
    client: httpx.Client | None = None,
) -> FrpBinaries:
    """Ensure ``frpc``/``frps`` for this host exist under ``install_dir``.

    Downloads and checksum-verifies the pinned release on first call; later
    calls are a no-op if the expected version is already installed.
    """
    install_dir.mkdir(parents=True, exist_ok=True)
    frpc_path = install_dir / "frpc"
    frps_path = install_dir / "frps"
    marker = install_dir / f".frp-{version}-installed"
    if frpc_path.exists() and frps_path.exists() and marker.exists():
        return FrpBinaries(frpc=frpc_path, frps=frps_path)

    arch = frp_arch(machine)
    asset = asset_name(arch, version=version)
    base = release_url(version)

    owns_client = client is None
    http = client or httpx.Client(follow_redirects=True, timeout=60.0)
    try:
        checksums_resp = http.get(f"{base}/{_CHECKSUMS_ASSET}")
        checksums_resp.raise_for_status()
        checksums = parse_checksums(checksums_resp.text)
        if asset not in checksums:
            raise UnsupportedArchitecture(f"{asset} not listed in {_CHECKSUMS_ASSET}")
        expected_digest = checksums[asset]

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive_path = tmp_path / asset
            with http.stream("GET", f"{base}/{asset}") as response:
                response.raise_for_status()
                with archive_path.open("wb") as out:
                    for chunk in response.iter_bytes():
                        out.write(chunk)

            actual_digest = sha256_of(archive_path)
            if actual_digest != expected_digest:
                raise ChecksumMismatch(
                    f"{asset}: expected sha256 {expected_digest}, got {actual_digest}"
                )

            with tarfile.open(archive_path) as tf:
                tf.extractall(tmp_path, filter="data")

            extracted_dir = tmp_path / asset.removesuffix(".tar.gz")
            for name, dest in (("frpc", frpc_path), ("frps", frps_path)):
                shutil.copy2(extracted_dir / name, dest)
                mode = dest.stat().st_mode
                dest.chmod(mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    finally:
        if owns_client:
            http.close()

    marker.write_text(version)
    return FrpBinaries(frpc=frpc_path, frps=frps_path)
