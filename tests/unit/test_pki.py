from cryptography import x509

from frp_jump.common.pki import CertificateAuthority


def test_bootstrap_creates_self_signed_ca() -> None:
    ca = CertificateAuthority.bootstrap("test CA")
    cert = x509.load_pem_x509_certificate(ca.cert_pem)
    assert cert.issuer == cert.subject


def test_issue_produces_cert_verifiable_by_the_issuing_ca() -> None:
    ca = CertificateAuthority.bootstrap("test CA")
    leaf = ca.issue("wb01")
    assert ca.verify_chain(leaf.cert_pem) is True


def test_verify_chain_rejects_cert_from_a_different_ca() -> None:
    ca_a = CertificateAuthority.bootstrap("ca-a")
    ca_b = CertificateAuthority.bootstrap("ca-b")
    leaf = ca_a.issue("wb01")
    assert ca_b.verify_chain(leaf.cert_pem) is False


def test_verify_chain_rejects_a_self_signed_cert_not_from_this_ca() -> None:
    ca = CertificateAuthority.bootstrap("test CA")
    rogue = CertificateAuthority.bootstrap("rogue")
    assert ca.verify_chain(rogue.cert_pem) is False


def test_from_pair_round_trips_a_persisted_ca() -> None:
    original = CertificateAuthority.bootstrap("test CA")
    restored = CertificateAuthority.from_pair(original.pair)
    leaf = restored.issue("wb01")
    assert restored.verify_chain(leaf.cert_pem) is True
    assert original.verify_chain(leaf.cert_pem) is True


def test_issued_cert_has_expected_common_name_and_san() -> None:
    ca = CertificateAuthority.bootstrap("test CA")
    leaf = ca.issue("wb01", san_names=["wb01", "wb01.local"])
    cert = x509.load_pem_x509_certificate(leaf.cert_pem)
    cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    assert cn == "wb01"
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert set(san.get_values_for_type(x509.DNSName)) == {"wb01", "wb01.local"}


def test_issue_encodes_ip_literal_sans_as_ip_address_not_dns_name() -> None:
    ca = CertificateAuthority.bootstrap("test CA")
    leaf = ca.issue("relay", san_names=["127.0.0.1", "relay.example.com"])
    cert = x509.load_pem_x509_certificate(leaf.cert_pem)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["relay.example.com"]
    assert [str(ip) for ip in san.get_values_for_type(x509.IPAddress)] == ["127.0.0.1"]


def test_serial_number_matches_certificate() -> None:
    ca = CertificateAuthority.bootstrap("test CA")
    leaf = ca.issue("wb01")
    cert = x509.load_pem_x509_certificate(leaf.cert_pem)
    assert leaf.serial_number == cert.serial_number
