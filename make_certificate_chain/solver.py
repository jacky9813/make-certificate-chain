import typing
import datetime
import warnings
import os

import cryptography.x509
import cryptography.x509.extensions
import requests

from .warnings import SelfSignCertificateWarning, NotValidYetWarning, NearExpirationWarning
from .exceptions import CertificateExpiredError, NoIssuerCertificateError


CERTIFICATE_BEGIN = "-----BEGIN CERTIFICATE-----"

SYSTEM_CA_FILE = [
    "/etc/ssl/certs/ca-certificates.crt",   # Debian, Alpine
    "/etc/ssl/certs/ca-bundle.crt"          # RHEL
]

def get_system_ca(
    path = None
) -> typing.Dict[str, cryptography.x509.Certificate]:
    """
        Get the certificates from the system's CA list.
    """
    if path is None:
        for p in SYSTEM_CA_FILE:
            if os.path.exists(p):
                path = p
                break
    with open(path, mode="r", encoding="utf-8") as ca_fd:
        ca = ca_fd.read()
    ca_list = [
        cryptography.x509.load_pem_x509_certificate(cert_pem)
        for cert_pem in [
            (CERTIFICATE_BEGIN + c).encode()
            for c in ca.split(CERTIFICATE_BEGIN)
            if c.strip() != ""
        ]
    ]
    return {
        ca_cert.issuer.rfc4514_string(): ca_cert
        for ca_cert in ca_list
    }


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
) -> cryptography.x509.Certificate:
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
    issuer_cert = None
    for issuer_link in issuer_aia:
        if issuer_link.access_method.dotted_string == "1.3.6.1.5.5.7.48.2":
            # The link to Issuer's Certificate
            # https://oidref.com/1.3.6.1.5.5.7.48.2
            cert_response = requests.get(issuer_link.access_location.value)
            try:
                issuer_cert = cryptography.x509.load_pem_x509_certificate(
                    cert_response.content
                )
                break
            except ValueError:
                issuer_cert = cryptography.x509.load_der_x509_certificate(
                    cert_response.content
                )
                break
    if issuer_cert is None:
        raise RuntimeError(
            f'Unable to retrieve CA certificate for'
            f'"{subject.issuer.rfc4514_string()}" from'
            f'{issuer_link.access_location.value}'
        )

    return issuer_cert


def solve_cert_chain(
    server_cert: cryptography.x509.Certificate,
    system_ca: typing.Optional[typing.Dict[str, cryptography.x509.Certificate]] = None,
    expire_warning: typing.Optional[datetime.timedelta] = None,
    include_root_ca: bool = False
) -> typing.Iterable[cryptography.x509.Certificate]:
    """
        Return a list that contains the certificate chain, with server certificate
        being the first element.

        The root CA's certificate will not be included.
    """
    if server_cert.issuer == server_cert.subject:
        verify_certificate(
            server_cert,
            server_cert,
            expire_warning
        )
        warnings.warn(
            "It is a self signed certificate.",
            SelfSignCertificateWarning
        )
        return [server_cert]
    if system_ca is None:
        system_ca = get_system_ca()
    chain = [server_cert]
    cursor = server_cert
    while True:
        issuer = cursor.issuer.rfc4514_string()
        if issuer in system_ca:
            verify_certificate(cursor, system_ca[issuer], expire_warning)
            if include_root_ca:
                chain.append(system_ca[issuer])
            break
        issuer_cert = get_issuer_certificate(cursor)
        verify_certificate(cursor, issuer_cert, expire_warning)
        chain.append(issuer_cert)
        cursor = issuer_cert
    return chain