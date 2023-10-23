import typing
import datetime
import warnings

import cryptography.x509
import cryptography.x509.extensions
import cryptography.hazmat.primitives.serialization.pkcs7 as pkcs7
import requests

from .warnings import SelfSignCertificateWarning, NotValidYetWarning, NearExpirationWarning, NotTrustedWarning
from .exceptions import CertificateExpiredError, NoIssuerCertificateError
from .utils import get_system_ca, CERTIFICATE_BEGIN


def verify_certificate(
    subject: cryptography.x509.Certificate,
    issuer: cryptography.x509.Certificate,
    expire_warning: typing.Optional[datetime.timedelta] = None
) -> None:
    """
        Verify a subject's certificate with:

        * Current time to not valid before and not valid after.
        * Issuer's distinguished name.
        * Issuer's public key (signature check).
    """
    current_time = datetime.datetime.utcnow()
    if current_time < subject.not_valid_before:
        warnings.warn(
            f'The certificate is valid after '
            f'{subject.not_valid_before.strftime("%Y-%m-%dT%H:%M:%SZ")}',
            NotValidYetWarning
        )
    if current_time > subject.not_valid_after:
        raise CertificateExpiredError(
            f'The certificate for {subject.subject.rfc4514_string()} is '
            f'expired at {subject.not_valid_after.strftime("%Y-%m-%dT%H:%M:%SZ")}'
        )
    if expire_warning is not None and \
        (current_time + expire_warning) > subject.not_valid_after:
        warnings.warn(
            f'The certificate is about to expire. '
            f'Expiration date: {subject.not_valid_after.strftime("%Y-%m-%dT%H:%M:%SZ")}',
            NearExpirationWarning
        )
    if subject.issuer.rfc4514_string() != issuer.subject.rfc4514_string():
        raise ValueError(
            "Issuer's distinguished name mismatch.\n"
            f'Issuer in subject certificate: {subject.issuer.rfc4514_string()}' "\n"
            f'Subject in issuer certificate: {issuer.subject.rfc4514_string()}'
        )
    issuer.public_key().verify(
        subject.signature,
        subject.tbs_certificate_bytes,
        cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
        subject.signature_hash_algorithm
    )


def get_issuer_certificate(
    subject: cryptography.x509.Certificate
) -> typing.Dict[str, typing.List[cryptography.x509.Certificate]]:
    """
        Tries to fetch the certificate listed in the certificate extension
        "Authority Information Access"
    """
    try:
        issuer_aia = subject.extensions.get_extension_for_class(
            cryptography.x509.AuthorityInformationAccess
        ).value
    except cryptography.x509.extensions.ExtensionNotFound:
        raise NoIssuerCertificateError(
            f'Unable to find the link for CA certificate '
            f'"{subject.issuer.rfc4514_string()}"'
        )
    issuer_certs: typing.List[cryptography.x509.Certificate] = []
    for issuer_link in issuer_aia:
        if issuer_link.access_method.dotted_string == "1.3.6.1.5.5.7.48.2":
            # The link to Issuer's Certificate
            # https://oidref.com/1.3.6.1.5.5.7.48.2
            issuer_cert_url: str = issuer_link.access_location.value
            cert_response = requests.get(issuer_cert_url)
            if issuer_cert_url.endswith("p7b"):
                # Expect PKCS7 format
                try:
                    issuer_certs = [
                        *issuer_certs,
                        *pkcs7.load_pem_pkcs7_certificates(cert_response.content)
                    ]
                except ValueError:
                    issuer_certs = [
                        *issuer_certs,
                        *pkcs7.load_der_pkcs7_certificates(cert_response.content)
                    ]
            else:
                try:
                    issuer_certs.append(cryptography.x509.load_pem_x509_certificate(
                        cert_response.content
                    ))
                    break
                except ValueError:
                    issuer_certs.append(cryptography.x509.load_der_x509_certificate(
                        cert_response.content
                    ))
                    break
    if not issuer_certs:
        raise RuntimeError(
            f'Unable to retrieve CA certificate for'
            f'"{subject.issuer.rfc4514_string()}" from'
            f'{issuer_link.access_location.value}'
        )

    cert_output: typing.Dict[str, typing.List[cryptography.x509.Certificate]] = {}
    for cert in issuer_certs:
        cert_subject = cert.subject.rfc4514_string()
        if cert_subject not in cert_output:
            cert_output[cert_subject] = list()
        cert_output[cert_subject].append(cert)
    
    return cert_output


def solve_cert_chain(
    current_cert: cryptography.x509.Certificate,
    ca_certificates: typing.Optional[typing.Dict[str, typing.List[cryptography.x509.Certificate]]] = None,
    expire_warning: typing.Optional[datetime.timedelta] = None,
    include_root_ca: bool = False,
    ignore_self_sign_warning: bool = False
) -> typing.Generator[cryptography.x509.Certificate, None, None]:
    """
        Return a list that contains the certificate chain, with server certificate
        being the first element.

        The root CA's certificate will not be included unless include_root_ca is True.
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
        ca_certificates = get_system_ca()
    
    issuer_name = current_cert.issuer.rfc4514_string()
    issuer_is_root_ca = False

    if issuer_name in ca_certificates and not include_root_ca:
        issuer_certs = ca_certificates[issuer_name]
        issuer_is_root_ca = True
    else:
        issuer_certs = get_issuer_certificate(current_cert).get(issuer_name, [])
    
    if not issuer_certs:
        raise NoIssuerCertificateError()
    
    for issuer_cert in issuer_certs:
        verify_certificate(current_cert, issuer_cert, expire_warning)

    if issuer_is_root_ca and not include_root_ca:
        return
    
    for issuer_cert in issuer_certs:
        for issuer_issuer_cert in solve_cert_chain(
            issuer_cert,
            ca_certificates,
            expire_warning,
            include_root_ca,
            issuer_is_root_ca or ignore_self_sign_warning
        ):
            yield issuer_issuer_cert
