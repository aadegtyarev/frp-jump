import subprocess

import pytest

from frp_jump.common import ssh_signing


@pytest.fixture
def keypair(tmp_path):
    key_path = tmp_path / "id_ed25519"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key_path), "-C", "test"],
        check=True,
        capture_output=True,
    )
    return key_path, key_path.with_suffix(".pub").read_text()


def test_fingerprint_is_stable(keypair):
    _, public_key = keypair
    assert ssh_signing.fingerprint(public_key).startswith("SHA256:")
    assert ssh_signing.fingerprint(public_key) == ssh_signing.fingerprint(public_key)


def test_fingerprint_differs_for_different_keys(tmp_path):
    key_a = tmp_path / "a"
    key_b = tmp_path / "b"
    for key_path in (key_a, key_b):
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key_path)],
            check=True,
            capture_output=True,
        )
    fp_a = ssh_signing.fingerprint(key_a.with_suffix(".pub").read_text())
    fp_b = ssh_signing.fingerprint(key_b.with_suffix(".pub").read_text())
    assert fp_a != fp_b


def test_sign_then_verify_round_trip(keypair):
    key_path, public_key = keypair
    signature = ssh_signing.sign(key_path, b"hello world")
    assert ssh_signing.verify(public_key, b"hello world", signature)


def test_verify_rejects_tampered_data(keypair):
    key_path, public_key = keypair
    signature = ssh_signing.sign(key_path, b"hello world")
    assert not ssh_signing.verify(public_key, b"goodbye world", signature)


def test_verify_rejects_wrong_key(keypair, tmp_path):
    key_path, _ = keypair
    other_key_path = tmp_path / "other"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(other_key_path)],
        check=True,
        capture_output=True,
    )
    other_public_key = other_key_path.with_suffix(".pub").read_text()
    signature = ssh_signing.sign(key_path, b"hello world")
    assert not ssh_signing.verify(other_public_key, b"hello world", signature)


def test_verify_rejects_wrong_namespace(keypair):
    key_path, public_key = keypair
    signature = ssh_signing.sign(key_path, b"hello world", namespace="some-other-namespace")
    assert not ssh_signing.verify(public_key, b"hello world", signature)


def test_fingerprint_rejects_garbage():
    with pytest.raises(ssh_signing.SshSigningError):
        ssh_signing.fingerprint("not a real key")
