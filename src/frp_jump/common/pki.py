"""Minimal private CA used to issue mTLS certificates for frps/frpc.

The server owns the CA. Every enrolled device gets its own key pair and a
leaf certificate signed by this CA; frps is configured to only accept peers
whose certificate chains to it (``transport.tls.trustedCaFile`` +
``force = true``), so an unenrolled device cannot reach the relay at all.
"""

from __future__ import annotations

import datetime
import ipaddress
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from cryptography.x509.oid import NameOID

_CURVE = ec.SECP256R1()
_CERT_VALIDITY = datetime.timedelta(days=825)
_CA_VALIDITY = datetime.timedelta(days=3650)
_CLOCK_SKEW = datetime.timedelta(minutes=5)


@dataclass(frozen=True, slots=True)
class KeyCertPair:
    """A private key plus its certificate, both PEM-encoded."""

    key_pem: bytes
    cert_pem: bytes

    @property
    def serial_number(self) -> int:
        return x509.load_pem_x509_certificate(self.cert_pem).serial_number


def _san_entries(names: list[str]) -> list[x509.GeneralName]:
    """Build SAN entries, using IPAddress (not DNSName) for IP literals.

    Go's TLS client only matches a cert against an IP host via an
    ``iPAddress`` SAN entry, never a ``dNSName`` one -- required so certs
    validate when ``serverAddr``/enroll addresses are bare IPs (as in
    loopback testing) and not just real hostnames.
    """
    entries: list[x509.GeneralName] = []
    for name in names:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            entries.append(x509.DNSName(name))
    return entries


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def _generate_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(_CURVE)


def _self_signed_ca(common_name: str) -> KeyCertPair:
    key = _generate_key()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    not_before = _now() - _CLOCK_SKEW
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + _CA_VALIDITY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    cert = builder.sign(key, hashes.SHA256())
    return KeyCertPair(
        key_pem=key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        cert_pem=cert.public_bytes(serialization.Encoding.PEM),
    )


class CertificateAuthority:
    """Wraps a CA key/cert pair and issues leaf certificates from it."""

    def __init__(self, ca: KeyCertPair) -> None:
        self._ca = ca
        self._key = serialization.load_pem_private_key(ca.key_pem, password=None)
        self._cert = x509.load_pem_x509_certificate(ca.cert_pem)

    @classmethod
    def bootstrap(cls, common_name: str = "frp-jump CA") -> CertificateAuthority:
        """Create a brand-new CA. Call once per server, persist the result."""
        return cls(_self_signed_ca(common_name))

    @classmethod
    def from_pair(cls, ca: KeyCertPair) -> CertificateAuthority:
        return cls(ca)

    @property
    def pair(self) -> KeyCertPair:
        return self._ca

    @property
    def cert_pem(self) -> bytes:
        return self._ca.cert_pem

    def issue(
        self, common_name: str, *, san_names: list[str] | None = None, server_auth: bool = False
    ) -> KeyCertPair:
        """Issue a leaf key+cert for a device or the relay, signed by this CA.

        ``san_names`` may mix hostnames and IP literals (e.g. a real domain
        for the relay, a bare IP for a loopback test); each is encoded as
        the correct SAN type automatically.

        ``server_auth`` gates the ``SERVER_AUTH`` EKU -- only the relay's
        own cert (``bootstrap.py``'s single ``ca.issue("relay", ...,
        server_auth=True)`` call) needs it, to present as frps's TLS
        identity. Every *device* cert defaults to ``CLIENT_AUTH`` only:
        `relay_public_addr` can only ever be a bare hostname/IP (dots are
        rejected by `registry.validate_name`, which every device name also
        goes through), but if a device were ever issued `SERVER_AUTH` too
        and happened to be named identically to it, that device could
        present a valid-looking relay identity to other devices from an
        on-path position -- there is no reason for a device cert to be
        able to do that.
        """
        key = _generate_key()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        not_before = _now() - _CLOCK_SKEW
        san = x509.SubjectAlternativeName(_san_entries(san_names or [common_name]))
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_before + _CERT_VALIDITY)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                        *([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH] if server_auth else []),
                    ]
                ),
                critical=False,
            )
            .add_extension(san, critical=False)
        )
        issuer_key: CertificateIssuerPrivateKeyTypes = self._key
        cert = builder.sign(issuer_key, hashes.SHA256())
        return KeyCertPair(
            key_pem=key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            cert_pem=cert.public_bytes(serialization.Encoding.PEM),
        )

    def verify_chain(self, cert_pem: bytes) -> bool:
        """True if ``cert_pem`` was issued by this CA and is currently valid.

        Test/debug helper only -- it checks the signature and validity
        window but not ``BasicConstraints``/``KeyUsage``/issuer-name match,
        so it is not a sound chain-validation primitive. Not used on any
        real auth path: actual mTLS chain verification is delegated to
        frp/Go (``transport.tls.trustedCaFile`` + ``force = true``), which
        is the right call. Do not start relying on this for access control.
        """
        cert = x509.load_pem_x509_certificate(cert_pem)
        try:
            self._cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        except Exception:
            return False
        now = _now()
        return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
