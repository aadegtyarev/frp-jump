from frp_jump.common.crypto import (
    generate_id,
    generate_token,
    hash_token,
    token_matches,
    write_private_key,
)


def test_generate_token_is_unique_and_reasonably_long() -> None:
    a, b = generate_token(), generate_token()
    assert a != b
    assert len(a) >= 32


def test_generate_id_is_unique() -> None:
    assert generate_id() != generate_id()


def test_hash_token_is_deterministic() -> None:
    token = generate_token()
    assert hash_token(token) == hash_token(token)


def test_hash_token_differs_for_different_tokens() -> None:
    assert hash_token(generate_token()) != hash_token(generate_token())


def test_token_matches_true_for_correct_pair() -> None:
    token = generate_token()
    assert token_matches(token, hash_token(token)) is True


def test_token_matches_false_for_wrong_token() -> None:
    token = generate_token()
    other = generate_token()
    assert token_matches(other, hash_token(token)) is False


def test_write_private_key_sets_restrictive_permissions(tmp_path) -> None:
    path = tmp_path / "key.pem"
    write_private_key(path, b"secret bytes")
    assert path.read_bytes() == b"secret bytes"
    mode = path.stat().st_mode & 0o777
    assert mode == 0o600


def test_write_private_key_overwrites_existing_file(tmp_path) -> None:
    path = tmp_path / "key.pem"
    write_private_key(path, b"old")
    write_private_key(path, b"new")
    assert path.read_bytes() == b"new"
