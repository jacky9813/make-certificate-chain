import typing
import logging
import getpass

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import NoEncryption

from .. import utils
from .. import solver


logger = logging.getLogger(__name__)

INFO_OUTPUT: typing.Dict[str, typing.Callable[[x509.Certificate], str]]={
    "Subject": lambda cert: cert.subject.rfc4514_string(),
    "Issuer": lambda cert: cert.issuer.rfc4514_string(),
    "Not Before": lambda cert: cert.not_valid_before_utc.strftime(
        "%Y-%m-%dT%H:%M:%SZ"),
    "Not After": lambda cert: cert.not_valid_after_utc.strftime(
        "%Y-%m-%dT%H:%M:%SZ")
}
PADDING_LENGTH = 12


CertificatePEM = str
CertificateChainPEM = str
PrivateKeyPEM = str


def output_info(cert: x509.Certificate) -> str:
    return "\n".join([
        " ".join([
            (" " * PADDING_LENGTH + field)[-PADDING_LENGTH:],
            ":",
            extractor(cert)
        ])
        for field, extractor in INFO_OUTPUT.items()
    ])


def build_pem_chain_and_key(
    cert_type: str,
    cert_raw: bytes,
    key_raw: typing.Optional[bytes] = None,
    key_pass: typing.Optional[bytes] = None,
    ca_path: typing.Optional[str] = None,
    skip_revoke_check: bool = False
) -> typing.Tuple[CertificatePEM, CertificateChainPEM, PrivateKeyPEM]:
    """
        Build certificate chain and private key in PEM format.

        Program will ask password if key_pass is None.
    """
    if key_pass is None:
        key_pass = getpass.getpass(
            "Password (leave blank if no password): "
        ).strip().encode()
    if not key_pass:
        key_pass = None

    ca_certs = utils.get_system_ca(ca_path)

    certs = utils.CERTIFICATE_FORMATS[cert_type](cert_raw, key_pass)
    if cert_type == "pkcs12":
        logger.info("Reading key from pkcs12 bundle.")
        key = utils.read_pkcs12_key(cert_raw, key_pass)
    else:
        logger.info("Reading keys from file.")
        if "PRIVATE KEY-----".encode() in key_raw:
            key = load_pem_private_key(key_raw, key_pass)
        else:
            key = load_der_private_key(key_raw, key_pass)

    logger.info("Comparing public keys in certificate and private key.")
    if key.public_key() != certs[0].public_key():
        raise Exception("Certificate's public key not matching the key file.")

    # This should create a key with -----BEGIN PRIVATE KEY-----
    # and not -----BEGIN ENCRYPTED PRIVATE KEY-----
    logger.info("Building PEM formatted PKCS8 private key.")
    key_pem = key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption()
    ).decode()
    logger.info("Building certificate chain in PEM format.")
    cert_pem_list = []
    logger.info("=" * PADDING_LENGTH)
    for cert in solver.solve_cert_chain(
        certs[0],
        ca_certs,
        skip_revoke_check=skip_revoke_check
    ):
        for line in output_info(cert).splitlines():
            logger.info(line)
        logger.info("=" * PADDING_LENGTH)
        cert_pem_list.append(cert.public_bytes(Encoding.PEM).decode())
    chain_pem = "\n".join(cert_pem_list)

    cert_pem = certs[0].public_bytes(Encoding.PEM).decode()

    return cert_pem, chain_pem, key_pem
