import pytest

from frp_jump.driver.frp.binaries import (
    UnsupportedArchitecture,
    asset_name,
    frp_arch,
    parse_checksums,
    sha256_of,
)


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
