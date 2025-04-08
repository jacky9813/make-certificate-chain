import typing
import datetime
import warnings

from cryptography import x509
from cryptography.x509 import extensions as x509_extensions
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
import requests

from .warnings import SelfSignCertificateWarning, NotValidYetWarning, NearExpirationWarning, NotTrustedWarning
from .exceptions import CertificateExpiredError, NoIssuerCertificateError
from . import utils


def verify_certificate(
    subject: x509.Certificate,
    issuer: x509.Certificate,
    expire_warning: typing.Optional[datetime.timedelta] = None,
    skip_ocsp_verification: bool = False
) -> None:
    """
        Verify a subject's certificate with:

        * Current time to not valid before and not valid after.
        * Issuer's distinguished name.
        * Issuer's public key (signature check).
    """
    current_time = datetime.datetime.now(datetime.timezone.utc)
    not_valid_before = subject.not_valid_before_utc
    not_valid_after = subject.not_valid_after_utc
    if current_time < not_valid_before:
        warnings.warn(
            f'The certificate is valid after '
            f'{not_valid_before.strftime("%Y-%m-%dT%H:%M:%SZ")}',
            NotValidYetWarning
        )
    if current_time > not_valid_after:
        raise CertificateExpiredError(
            f'The certificate for {subject.subject.rfc4514_string()} is '
            f'expired at {not_valid_after.strftime("%Y-%m-%dT%H:%M:%SZ")}'
        )
    if expire_warning is not None and \
        (current_time + expire_warning) > not_valid_after:
        warnings.warn(
            f'The certificate is about to expire. '
            f'Expiration date: {not_valid_after.strftime("%Y-%m-%dT%H:%M:%SZ")}',
            NearExpirationWarning
        )
    if subject.issuer.rfc4514_string() != issuer.subject.rfc4514_string():
        raise ValueError(
            "Issuer's distinguished name mismatch.\n"
            f'Issuer in subject certificate: {subject.issuer.rfc4514_string()}' "\n"
            f'Subject in issuer certificate: {issuer.subject.rfc4514_string()}'
        )
    issuer_public_key = issuer.public_key()
    if isinstance(issuer_public_key, dsa.DSAPublicKey):
        issuer_public_key.verify(
            subject.signature,
            subject.tbs_certificate_bytes,
            subject.signature_hash_algorithm
        )
    elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
        issuer_public_key.verify(
            subject.signature,
            subject.tbs_certificate_bytes,
            subject.signature_algorithm_parameters
        )
    elif isinstance(
        issuer_public_key,
        (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)
    ):
        issuer_public_key.verify(
            subject.signature,
            subject.tbs_certificate_bytes
        )
    elif isinstance(issuer_public_key, rsa.RSAPublicKey):
        issuer.public_key().verify(
            subject.signature,
            subject.tbs_certificate_bytes,
            PKCS1v15(),
            subject.signature_hash_algorithm
        )

    if subject != issuer and not skip_ocsp_verification:
        # Self-signed certificate cannot be revoked, I suppose?
        utils.verify_against_ocsp(subject, issuer)


def get_issuer_certificate(subject: x509.Certificate) -> utils.CertificateList:
    """
        Tries to fetch the certificate listed in the certificate extension
        "Authority Information Access"
    """
    try:
        issuer_aia = subject.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess
        ).value
    except x509_extensions.ExtensionNotFound:
        raise NoIssuerCertificateError(
            f'Unable to find the link for CA certificate '
            f'"{subject.issuer.rfc4514_string()}"'
        )
    issuer_certs: typing.List[x509.Certificate] = []
    for issuer_link in issuer_aia:
        if issuer_link.access_method.dotted_string == "1.3.6.1.5.5.7.48.2":
            # The link to Issuer's Certificate
            # https://oidref.com/1.3.6.1.5.5.7.48.2
            issuer_cert_url: str = issuer_link.access_location.value
            cert_response: requests.Response = requests.get(issuer_cert_url)
            if issuer_cert_url.endswith("p7b"):
                # Expect PKCS7 format
                issuer_certs.extend(
                    utils.read_pkcs7_certificates(cert_response.content)
                )
            else:
                issuer_certs.extend(
                    utils.read_x509_certificates(cert_response.content)
                )
    if not issuer_certs:
        raise RuntimeError(
            f'Unable to retrieve CA certificate for'
            f'"{subject.issuer.rfc4514_string()}" from'
            f'{issuer_link.access_location.value}'
        )

    cert_output: utils.CertificateList = {}
    for cert in issuer_certs:
        cert_subject = cert.subject.rfc4514_string()
        if cert_subject not in cert_output:
            cert_output[cert_subject] = list()
        cert_output[cert_subject].append(cert)

    return cert_output


def solve_cert_chain(
    current_cert: x509.Certificate,
    ca_certificates: typing.Optional[utils.CertificateList] = None,
    expire_warning: typing.Optional[datetime.timedelta] = None,
    include_root_ca: bool = False,
    ignore_self_sign_warning: bool = False,
    known_certificates: typing.Optional[utils.CertificateList] = None
) -> typing.Generator[x509.Certificate, None, None]:
    """
        Return a list that contains the certificate chain, with server
        certificate being the first element.

        The root CA's certificate will not be included unless include_root_ca
        is True.
    """
    yield current_cert
    if current_cert.issuer == current_cert.subject:
        verify_certificate(
            current_cert,
            current_cert,
            expire_warning
        )
        if not ignore_self_sign_warning:
            warnings.warn(
                "It is a self signed certificate.",
                SelfSignCertificateWarning
            )
        return

    if ca_certificates is None:
        ca_certificates = utils.get_system_ca()

    if known_certificates is None:
        known_certificates = dict()

    issuer_name = current_cert.issuer.rfc4514_string()
    issuer_is_root_ca = False
    issuer_already_known = False

    if issuer_name in known_certificates:
        issuer_certs = known_certificates[issuer_name]
        issuer_already_known = True
    elif issuer_name in ca_certificates:
        issuer_certs = ca_certificates[issuer_name]
        issuer_is_root_ca = True
    else:
        issuer_certs = get_issuer_certificate(current_cert).get(issuer_name, [])
        known_certificates[issuer_name] = issuer_certs

    if not issuer_certs:
        raise NoIssuerCertificateError()

    while True:
        issuer_cert = issuer_certs.pop()
        try:
            verify_certificate(current_cert, issuer_cert, expire_warning)
        except Exception:
            if issuer_certs:
                continue
            raise
        break

    if issuer_already_known:
        raise Exception("Loop detected in certificate chain.")

    if issuer_cert.subject == issuer_cert.issuer and not issuer_is_root_ca:
        issuer_is_root_ca = True
        warnings.warn(
            "Root CA is unknown to this system",
            NotTrustedWarning
        )

    if issuer_is_root_ca and not include_root_ca:
        return

    yield from solve_cert_chain(
        issuer_cert,
        ca_certificates,
        expire_warning,
        include_root_ca,
        issuer_is_root_ca or ignore_self_sign_warning,
        known_certificates
    )
