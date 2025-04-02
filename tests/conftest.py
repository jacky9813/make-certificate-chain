import datetime
import ssl

from cryptography import x509
from cryptography.x509 import extensions as x509_extensions
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, Encoding
import pytest

from make_certificate_chain import solver

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
def cert_with_invalid_signature() -> x509.Certificate:
    another_cert_str = ssl.get_server_certificate(("www.example.com", 443))
    another_cert = x509.load_pem_x509_certificate(another_cert_str.encode())

    ca_dn = another_cert.issuer
    ca_aia = another_cert.extensions.get_extension_for_class(
        x509_extensions.AuthorityInformationAccess
    )
    ca_cert = solver.get_issuer_certificate(
        another_cert)[ca_dn.rfc4514_string()][0]
    true_ca_public_key = ca_cert.public_key()

    if isinstance(true_ca_public_key, rsa.RSAPublicKey):
        invalid_ca_key = rsa.generate_private_key(
            65537,
            ca_cert.public_key().key_size
        )
    elif isinstance(true_ca_public_key, ec.EllipticCurvePublicKey):
        invalid_ca_key = ec.generate_private_key(
            true_ca_public_key.curve
        )
    private_key = rsa.generate_private_key(65537, 2048)
    FQDN = "just.testing"
    dn = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TW"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Just testing"),
        x509.NameAttribute(NameOID.COMMON_NAME, FQDN)
    ])
    cert = x509.CertificateBuilder(
        issuer_name=ca_dn,
        subject_name=dn,
        public_key=private_key.public_key(),
        serial_number=x509.random_serial_number(),
        not_valid_before=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30),
        not_valid_after=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(FQDN)]),
        critical=False
    ).add_extension(
        x509.AuthorityInformationAccess(ca_aia.value),
        critical=False
    )
    if isinstance(invalid_ca_key, rsa.RSAPrivateKey):
        cert = cert.sign(
            private_key=invalid_ca_key,
            algorithm=hashes.SHA256()
        )
    elif isinstance(invalid_ca_key, ec.EllipticCurvePrivateKey):
        cert = cert.sign(
            private_key=invalid_ca_key,
            algorithm=hashes.SHA384()
        )
    return cert



@pytest.fixture
def example_com_cert() -> bytes:
    # Testing X509 certificate
    cert = ssl.get_server_certificate(("www.example.com", 443))
    return cert.encode()


@pytest.fixture
def example_com_cert_pkcs12() -> bytes:
    cert = ssl.get_server_certificate(("www.example.com", 443))
    return pkcs12.serialize_key_and_certificates(
        name=None,
        key=None,
        cert=x509.load_pem_x509_certificate(cert.encode()),
        cas=None,
        encryption_algorithm=BestAvailableEncryption(b'12345678')
    )


@pytest.fixture
def epki_com_tw_cert() -> bytes:
    # Testing PKCS7 certificates
    cert = ssl.get_server_certificate(("epki.com.tw", 443))
    return pkcs7.serialize_certificates(
        [x509.load_pem_x509_certificate(cert.encode())],
        encoding=Encoding.PEM
    )
