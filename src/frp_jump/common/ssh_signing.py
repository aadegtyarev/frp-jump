"""SSH-key based identity: fingerprinting and challenge-response signing.

Uses OpenSSH's own ``ssh-keygen -Y sign`` / ``-Y verify`` (the same
mechanism git uses for SSH-signed commits) instead of a Python crypto
library, so a user's ordinary ``~/.ssh/id_ed25519`` keypair works as-is,
in whatever format ``ssh-keygen`` already understands, with no conversion.
``ssh-keygen`` is a standing dependency everywhere this runs (the OpenSSH
client), same as the OS's ``ssh``/``scp`` themselves.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

#: Namespace tag for `-Y sign`/`-Y verify` -- scopes a signature to this
#: use so it can never be replayed as, say, a git-commit signature.
NAMESPACE = "frp-jump-enroll"

#: Fixed principal name for the single-key allowed-signers file `verify`
#: builds on the fly -- there is only ever one candidate key per
#: verification call (the caller already looked it up by fingerprint), so
#: this never needs to disambiguate between multiple identities.
_PRINCIPAL = "frp-jump"

# `fingerprint`/`verify` run against untrusted, sometimes-unauthenticated
# input (e.g. POST /enroll/challenge's public_key, before any user is
# known to exist) -- an unbounded subprocess call there is a request-
# thread-exhaustion DoS waiting to happen. Local ssh-keygen invocations
# never legitimately take anywhere near this long.
_SUBPROCESS_TIMEOUT_SECONDS = 10.0


class SshSigningError(RuntimeError):
    """`ssh-keygen` failed, timed out, or produced unparseable output."""


def _run(
    args: list[str],
    *,
    input_bytes: bytes | None = None,
    timeout: float = _SUBPROCESS_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            args, input=input_bytes, capture_output=True, timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        raise SshSigningError(f"{' '.join(args)} timed out after {timeout}s") from exc
    if result.returncode != 0:
        raise SshSigningError(
            f"{' '.join(args)} failed (exit {result.returncode}): "
            f"{result.stderr.decode(errors='replace').strip()}"
        )
    return result


def canonicalize(public_key_text: str) -> str:
    """Validate that ``public_key_text`` is exactly one SSH public key
    line, and return it stripped of surrounding whitespace.

    Rejects anything containing an embedded newline. This matters because
    ``ssh-keygen -l`` only ever reports the fingerprint of the *first* key
    in a file -- silently accepting a multi-key blob here would let a
    fingerprint be computed from one key while a *different* key in the
    same blob remains valid for ``-Y verify`` (an allowed-signers file is
    one-key-per-line and matches any of them), so a crafted two-line
    input could pass as someone else's registered fingerprint while
    actually authenticating with an attacker-controlled key. Every
    caller -- fingerprinting *and* verifying -- must go through this.
    """
    text = public_key_text.strip()
    if not text:
        raise SshSigningError("empty public key")
    if "\n" in text or "\r" in text:
        raise SshSigningError("expected exactly one SSH public key, got multiple lines")
    return text


def fingerprint(public_key_text: str) -> str:
    """Return the ``SHA256:...`` fingerprint of a public key, exactly as
    it would appear in ``ssh-keygen -l -f ~/.ssh/id_ed25519.pub``."""
    text = canonicalize(public_key_text)
    with tempfile.TemporaryDirectory() as tmp:
        pub_path = Path(tmp) / "key.pub"
        pub_path.write_text(text + "\n")
        result = _run(["ssh-keygen", "-l", "-f", str(pub_path)])
    for part in result.stdout.decode().split():
        if part.startswith("SHA256:"):
            return part
    raise SshSigningError(f"could not parse a fingerprint from: {result.stdout!r}")


def sign(identity_path: Path, data: bytes, *, namespace: str = NAMESPACE) -> bytes:
    """Sign ``data`` with the private key at ``identity_path`` (e.g.
    ``~/.ssh/id_ed25519``), returning the raw armored ``-Y sign`` signature."""
    with tempfile.TemporaryDirectory() as tmp:
        data_path = Path(tmp) / "data"
        data_path.write_bytes(data)
        _run(
            ["ssh-keygen", "-Y", "sign", "-f", str(identity_path), "-n", namespace, str(data_path)]
        )
        sig_path = data_path.parent / f"{data_path.name}.sig"
        return sig_path.read_bytes()


def verify(
    public_key_text: str,
    data: bytes,
    signature: bytes,
    *,
    namespace: str = NAMESPACE,
) -> bool:
    """Verify ``signature`` over ``data`` was produced by the private key
    matching ``public_key_text``. Returns ``False`` for a bad signature,
    wrong namespace, malformed input, or a multi-line/non-canonical key
    (see ``canonicalize``) -- never raises for those, since "verification
    failed" is an expected, non-exceptional outcome here."""
    try:
        text = canonicalize(public_key_text)
    except SshSigningError:
        return False
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        allowed_signers = tmp_path / "allowed_signers"
        allowed_signers.write_text(f"{_PRINCIPAL} {text}\n")
        sig_path = tmp_path / "data.sig"
        sig_path.write_bytes(signature)
        try:
            result = subprocess.run(
                [
                    "ssh-keygen",
                    "-Y",
                    "verify",
                    "-f",
                    str(allowed_signers),
                    "-I",
                    _PRINCIPAL,
                    "-n",
                    namespace,
                    "-s",
                    str(sig_path),
                ],
                input=data,
                capture_output=True,
                timeout=_SUBPROCESS_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return False
        return result.returncode == 0
