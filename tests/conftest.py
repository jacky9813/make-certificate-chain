import datetime
import ssl

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest


@pytest.fixture
def self_sign_cert() -> x509.Certificate:
    private_key = rsa.generate_private_key(65537, 2048)
    FQDN = "just.testing"
    dn = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TW"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Just testing"),
        x509.NameAttribute(NameOID.COMMON_NAME, FQDN)
    ])
    cert = x509.CertificateBuilder(
        issuer_name=dn, subject_name=dn,
        public_key=private_key.public_key(), serial_number=x509.random_serial_number(),
        not_valid_before=datetime.datetime.utcnow() - datetime.timedelta(days=1),
        not_valid_after=datetime.datetime.utcnow() + datetime.timedelta(days=1),
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(FQDN)]),
        critical=False
    ).sign(private_key=private_key, algorithm=hashes.SHA256())
    return cert


@pytest.fixture
def self_sign_cert_expired() -> x509.Certificate:
    private_key = rsa.generate_private_key(65537, 2048)
    FQDN = "just.testing"
    dn = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TW"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Just testing"),
        x509.NameAttribute(NameOID.COMMON_NAME, FQDN)
    ])
    cert = x509.CertificateBuilder(
        issuer_name=dn, subject_name=dn,
        public_key=private_key.public_key(), serial_number=x509.random_serial_number(),
        not_valid_before=datetime.datetime.utcnow() - datetime.timedelta(days=30),
        not_valid_after=datetime.datetime.utcnow() - datetime.timedelta(days=1),
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(FQDN)]),
        critical=False
    ).sign(private_key=private_key, algorithm=hashes.SHA256())
    return cert


@pytest.fixture
def cert_with_unknown_ca() -> x509.Certificate:
    ca_private_key = rsa.generate_private_key(65537, 2048)
    private_key = rsa.generate_private_key(65537, 2048)
    FQDN = "just.testing"
    ca_dn = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TW"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Just testing CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, FQDN)
    ])
    dn = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TW"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Just testing"),
        x509.NameAttribute(NameOID.COMMON_NAME, FQDN)
    ])
    cert = x509.CertificateBuilder(
        issuer_name=ca_dn, subject_name=dn,
        public_key=private_key.public_key(), serial_number=x509.random_serial_number(),
        not_valid_before=datetime.datetime.utcnow() - datetime.timedelta(days=30),
        not_valid_after=datetime.datetime.utcnow() + datetime.timedelta(days=1),
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(FQDN)]),
        critical=False
    ).sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    return cert


@pytest.fixture
def example_com_cert() -> x509.Certificate:
    cert = ssl.get_server_certificate(("www.example.com", 443))
    return x509.load_pem_x509_certificate(cert.encode())
