import hashlib
import io
import tarfile

import httpx
import pytest

from frp_jump.driver.frp.binaries import (
    ChecksumMismatch,
    UnsupportedArchitecture,
    asset_name,
    ensure_installed,
    frp_arch,
    parse_checksums,
    sha256_of,
)

_VERSION = "0.70.0"
_ASSET = f"frp_{_VERSION}_linux_amd64.tar.gz"
_BASE = f"https://github.com/fatedier/frp/releases/download/v{_VERSION}"


def _fake_tarball(
    *, frpc_content: bytes = b"fake-frpc", frps_content: bytes = b"fake-frps"
) -> bytes:
    buf = io.BytesIO()
    top = _ASSET.removesuffix(".tar.gz")
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in (("frpc", frpc_content), ("frps", frps_content)):
            info = tarfile.TarInfo(name=f"{top}/{name}")
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _fake_client(tarball: bytes, checksums_text: str) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("frp_sha256_checksums.txt"):
            return httpx.Response(200, text=checksums_text)
        if request.url.path.endswith(_ASSET):
            return httpx.Response(200, content=tarball)
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler))


@pytest.mark.parametrize(
    ("machine", "expected"),
    [
        ("x86_64", "amd64"),
        ("amd64", "amd64"),
        ("aarch64", "arm64"),
        ("arm64", "arm64"),
        ("armv7l", "arm_hf"),
        ("armv6l", "arm"),
    ],
)
def test_frp_arch_maps_known_machines(machine: str, expected: str) -> None:
    assert frp_arch(machine) == expected


def test_frp_arch_rejects_unknown_machine() -> None:
    with pytest.raises(UnsupportedArchitecture):
        frp_arch("sparc64")


def test_asset_name_matches_upstream_naming_convention() -> None:
    assert asset_name("amd64", version="0.70.0") == "frp_0.70.0_linux_amd64.tar.gz"


def test_parse_checksums_handles_sha256sum_format() -> None:
    text = (
        "deadbeef  frp_0.70.0_linux_amd64.tar.gz\n"
        "cafebabe  frp_0.70.0_linux_arm64.tar.gz\n"
    )
    checksums = parse_checksums(text)
    assert checksums["frp_0.70.0_linux_amd64.tar.gz"] == "deadbeef"
    assert checksums["frp_0.70.0_linux_arm64.tar.gz"] == "cafebabe"


def test_parse_checksums_ignores_blank_lines() -> None:
    text = "deadbeef  a.tar.gz\n\n\ncafebabe  b.tar.gz\n"
    assert len(parse_checksums(text)) == 2


def test_sha256_of_matches_known_digest(tmp_path) -> None:
    path = tmp_path / "f.bin"
    path.write_bytes(b"hello world")
    assert (
        sha256_of(path) == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    )


def test_ensure_installed_with_correct_checksum_installs_executable_binaries(tmp_path) -> None:
    tarball = _fake_tarball()
    digest = hashlib.sha256(tarball).hexdigest()
    client = _fake_client(tarball, f"{digest}  {_ASSET}\n")

    result = ensure_installed(tmp_path, version=_VERSION, machine="x86_64", client=client)

    assert result.frpc.read_bytes() == b"fake-frpc"
    assert result.frps.read_bytes() == b"fake-frps"
    assert result.frpc.stat().st_mode & 0o111  # executable bit set


def test_ensure_installed_raises_checksum_mismatch_on_tampered_download(tmp_path) -> None:
    """The one supply-chain control in the download path: a tarball that
    does not match the published digest must be rejected, not installed."""
    tarball = _fake_tarball()
    wrong_digest = "0" * 64
    client = _fake_client(tarball, f"{wrong_digest}  {_ASSET}\n")

    with pytest.raises(ChecksumMismatch):
        ensure_installed(tmp_path, version=_VERSION, machine="x86_64", client=client)

    assert not (tmp_path / "frpc").exists()
    assert not (tmp_path / "frps").exists()


def test_ensure_installed_raises_when_asset_missing_from_checksums(tmp_path) -> None:
    tarball = _fake_tarball()
    client = _fake_client(tarball, "deadbeef  some_other_file.tar.gz\n")

    with pytest.raises(UnsupportedArchitecture):
        ensure_installed(tmp_path, version=_VERSION, machine="x86_64", client=client)


def test_ensure_installed_is_a_noop_on_second_call(tmp_path) -> None:
    tarball = _fake_tarball()
    digest = hashlib.sha256(tarball).hexdigest()
    client = _fake_client(tarball, f"{digest}  {_ASSET}\n")
    ensure_installed(tmp_path, version=_VERSION, machine="x86_64", client=client)

    def boom(request: httpx.Request) -> httpx.Response:
        raise AssertionError("should not hit the network on an already-installed version")

    second_client = httpx.Client(transport=httpx.MockTransport(boom))
    result = ensure_installed(tmp_path, version=_VERSION, machine="x86_64", client=second_client)
    assert result.frpc.read_bytes() == b"fake-frpc"
