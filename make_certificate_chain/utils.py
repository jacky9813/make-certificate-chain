import base64
import getpass
import glob
import itertools
import logging
import os
import re
import secrets
import ssl
import subprocess
import sys
import typing
import urllib.parse

import certifi
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.hashes import SHA1, SHA256
import requests
import urllib3.exceptions

from . import exceptions


CERTIFICATE_BEGIN = "-----BEGIN CERTIFICATE-----"
CERTIFICATE_RE = re.compile(
    r"((?:-{5}BEGIN CERTIFICATE-{5})"
    r"[0-9a-zA-Z+/=\r\n]+"
    r"(?:-{5}END CERTIFICATE-{5}))"
)
PKCS7_BEGIN = "-----BEGIN PKCS7-----"

OCSP_REQ_MIME = "application/ocsp-request"
OCSP_RESP_MIME = "application/ocsp-response"

CertificateList = typing.Dict[str, typing.List[x509.Certificate]]

logger = logging.getLogger(__name__)


def _error(*msg, exc_type: Exception, raise_error: bool = True):
    if raise_error:
        raise exc_type(*msg)
    logger.error(*msg)


def read_x509_certificates(
    raw_data: bytes,
    password: typing.Optional[bytes] = None
) -> typing.List[x509.Certificate]:
    try:
        str_data = raw_data.decode()
    except UnicodeDecodeError:
        str_data = None
    if str_data:
        return [
            x509.load_pem_x509_certificate(match.group(1).encode())
            for match in CERTIFICATE_RE.finditer(str_data)
        ]
    return [x509.load_der_x509_certificate(raw_data)]


def read_pkcs7_certificates(
    raw_data: bytes,
    password: typing.Optional[bytes] = None
) -> typing.List[x509.Certificate]:
    if PKCS7_BEGIN.encode() in raw_data:
        return pkcs7.load_pem_pkcs7_certificates(raw_data)
    return pkcs7.load_der_pkcs7_certificates(raw_data)


def read_pkcs12_certificates(
    raw_data: bytes,
    password: typing.Optional[bytes] = None
) -> typing.List[x509.Certificate]:
    parsed_p12 = pkcs12.load_pkcs12(
        raw_data,
        password or getpass.getpass(
            prompt="PKCS#12 password: ").strip().encode()
    )
    # If there's no key in the PKCS#12, parsed_p12.cert will be None
    return [
        parsed_p12.cert.certificate
    ] if parsed_p12.cert else [
        p12_cert.certificate
        for p12_cert in parsed_p12.additional_certs
    ]


CERTIFICATE_FORMATS: typing.Dict[
    str,
    typing.Callable[
        [bytes, typing.Optional[bytes]],
        typing.List[x509.Certificate]
    ]
] = {
    "x509": read_x509_certificates,
    "pkcs7": read_pkcs7_certificates,
    "pkcs12": read_pkcs12_certificates
}


def read_pkcs12_key(
    pkcs12_raw: bytes,
    password: typing.Optional[bytes] = None
) -> typing.Optional[PrivateKeyTypes]:
    parsed_p12 = pkcs12.load_pkcs12(pkcs12_raw, password)
    return parsed_p12.key


def read_certificate_file(
    path: str,
    cert_fmt: str = "x509"
) -> typing.List[x509.Certificate]:
    with open(path, mode="rb") as cert_fd:
        certs = CERTIFICATE_FORMATS[cert_fmt](cert_fd.read())
    return certs


def get_system_ca(path = None) -> CertificateList:
    """
        Get the certificates from the system's CA list.
    """
    if path:
        if os.path.isdir(path):
            ca_list = list(itertools.chain(*[
                read_certificate_file(os.path.join(path, filepath))
                for filepath in [
                    os.path.join(path, filename)
                    for filename in os.listdir(path)
                ]
            ]))
        else:
            ca_list = read_certificate_file(path)
    elif sys.platform == "win32":
        ca_list = [
            x509.load_der_x509_certificate(ca_info[0])
            for ca_info in ssl.enum_certificates("root")
        ]
    elif sys.platform == "darwin":
        try:
            # https://apple.stackexchange.com/a/436177
            # https://www.unix.com/man-page/osx/1/security/

            # I'm not using macos. I can't verify the following command
            # would work or not.
            security_process = subprocess.run(
                ["security", "find-certificate", "-a", "-p"],
                capture_output=True,
                shell=True,
                check=True
            )
            ca_pem_raw = security_process.stdout
        except subprocess.CalledProcessError:
            # If the command failed, use certificates in certifi package.
            with open(certifi.where(), mode="rb") as cert_fd:
                ca_pem_raw = cert_fd.read()
        ca_list = read_x509_certificates(ca_pem_raw)
    else:
        openssl_capath = ssl.get_default_verify_paths().openssl_capath
        ca_list = itertools.chain(*[
            read_certificate_file(ca_cert)
            for ca_cert in glob.glob(os.path.join(openssl_capath, "*"))
            if os.path.isfile(ca_cert)
        ])

    output: typing.Dict[str, typing.List[x509.Certificate]] = {}
    for ca_cert in ca_list:
        ca_subject = ca_cert.subject.rfc4514_string()
        if ca_subject not in output:
            output[ca_subject] = list()

        # Deduplicate the same certificate.
        if ca_cert.signature not in [
            known_cert.signature
            for known_cert in output[ca_subject]
        ]:
            output[ca_subject].append(ca_cert)

    return output


def get_ocsp_link(cert: x509.Certificate) -> typing.Optional[str]:
    "Get the link for OCSP from Authority Information Access extension"
    try:
        cert_aia = cert.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess)
    except x509.ExtensionNotFound:
        logger.warning(
            "Certificate %s (%s) does not contain Authority Information "
            "Access extension",
            cert.serial_number.to_bytes(16).hex().upper(),
            cert.subject.rfc4514_string()
        )
        return
    try:
        link = next(iter([
            aia_value.access_location.value
            for aia_value in cert_aia.value
            if aia_value.access_method._name == "OCSP"
        ]))
    except StopIteration:
        return
    return link


def verify_against_ocsp(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    hash: typing.Union[SHA1, SHA256, None] = None,
    raise_error: bool = True,
    fallback_to_sha1: bool = True,
    try_get_method: bool = False,
    check_nonce: bool = False  # OCSP Nonce is broken for now
) -> typing.Optional[bool]:
    "Check revocation"
    if not isinstance(cert, x509.Certificate):
        raise TypeError(
            "cert is not an instance of cryptography.x509.Certificate. Did "
            "you forget to parse it first?"
        )
    if not isinstance(issuer, x509.Certificate):
        raise TypeError(
            "issuer is not an instance of cryptography.x509.Certificate. Did "
            "you forget to parse it first?"
        )
    if hash is None:
        hash = SHA256()
    if not isinstance(hash, (SHA1, SHA256)):
        raise TypeError("Only SHA1 and SHA256 are supported")
    if check_nonce:
        nonce = secrets.token_bytes(16)
        ocsp_nonce = x509.OCSPNonce(nonce)
    ocsp_request_builder = ocsp.OCSPRequestBuilder(
        (cert, issuer, hash),
        extensions=[
            x509.Extension(x509.OCSPNonce.oid, True, ocsp_nonce)
        ] if check_nonce else []
    )
    ocsp_request = ocsp_request_builder.build()

    ocsp_request_raw = ocsp_request.public_bytes(Encoding.DER)
    ocsp_request_b64_url = urllib.parse.quote(
        base64.b64encode(ocsp_request_raw),
        safe=""
    )
    ocsp_link = get_ocsp_link(cert)
    if not ocsp_link:
        if raise_error:
            raise ValueError(
                "cert does not contain Authority Information Access extension "
                "with OCSP endpoint."
            )
        logger.error(
            "cert does not contain Authority Information Access extension "
            "with OCSP endpoint."
        )
        return
    if (
        not ocsp_link.startswith("http://") and
        not ocsp_link.startswith("https://")
    ):
        _error(
            "Non-HTTP(S) OCSP Stapling endpoint not supported",
            exc_type=NotImplementedError, raise_error=raise_error
        )
        return
    ocsp_get_url = urllib.parse.urljoin(ocsp_link, ocsp_request_b64_url)

    try:
        if len(ocsp_get_url) > 255 or not try_get_method:
            using_get = False
            response = requests.post(
                ocsp_link,
                data=ocsp_request_raw,
                headers={
                    "Content-Type": OCSP_REQ_MIME,
                    "Accept": OCSP_RESP_MIME
                }
            )
        else:
            using_get = True
            response = requests.get(
                ocsp_get_url,
                headers={"Accept": OCSP_RESP_MIME}
            )
    except (requests.ConnectionError, urllib3.exceptions.SSLError) as e:
        if using_get:
            logger.info("Fallback to POST method")
            return verify_against_ocsp(
                cert=cert, issuer=issuer, hash=type(hash)(),
                raise_error=raise_error, fallback_to_sha1=fallback_to_sha1,
                try_get_method=False, check_nonce=check_nonce
            )
        logger.exception("Failed to connect to %s", ocsp_link)
        if raise_error:
            raise
        return

    try:
        response.raise_for_status()
    except requests.HTTPError:
        if response.request.method == "GET":
            logger.warning("GET method not supported for %s", ocsp_link)
            logger.info("Fallback to POST method")
            return verify_against_ocsp(
                cert=cert, issuer=issuer, hash=type(hash)(),
                raise_error=raise_error, fallback_to_sha1=fallback_to_sha1,
                try_get_method=False, check_nonce=check_nonce
            )
        if raise_error:
            raise
        return

    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    if ocsp_response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        if isinstance(hash, SHA256) and fallback_to_sha1:
            logger.warning(
                "Failed to use SHA256 to call OCSP. Falling back to SHA1."
            )
            return verify_against_ocsp(cert, issuer, SHA1())
        _error(
            f"OCSP server \"{ocsp_link}\" Respond with "
            f"{ocsp_response.response_status.name}",
            exc_type=Exception, raise_error=raise_error
        )
        return

    if check_nonce:
        response_nonce = ocsp_response.extensions.get_extension_for_class(
            x509.OCSPNonce
        )
        if response_nonce.value.nonce != nonce:
            _error(
                "Failed to check nonce in OCSP response",
                exc_type=exceptions.OCSPNonceFailed, raise_error=raise_error
            )
            return
    if ocsp_response.certificate_status != ocsp.OCSPCertStatus.GOOD:
        _error(
            "OCSP status for %s is %s", cert.subject.rfc4514_string(),
            ocsp_response.certificate_status.name,
            exc_type=exceptions.OCSPVerificationFailed, raise_error=raise_error
        )
    return ocsp_response.certificate_status == ocsp.OCSPCertStatus.GOOD


def get_crl_download_link(cert: x509.Certificate) -> typing.Optional[str]:
    crl_dp = None
    try:
        crl_dp = cert.extensions.get_extension_for_class(
            x509.CRLDistributionPoints)
    except x509.ExtensionNotFound:
        pass
    if crl_dp and len(crl_dp.value):
        return crl_dp.value[0].full_name[0].value


def load_x509_crl(raw: bytes) -> x509.CertificateRevocationList:
    if b'-----BEGIN X509 CRL-----' in raw:
        try:
            return x509.load_pem_x509_crl(raw)
        except ValueError:
            pass
    return x509.load_der_x509_crl(raw)


def get_crl_from_cert(
    cert: x509.Certificate,
    raise_error: bool = True
) -> typing.Optional[x509.CertificateRevocationList]:
    download_link = get_crl_download_link(cert)
    if not download_link:
        _error(
            "Unable to get CRL distribution point from certificate",
            exc_type=ValueError, raise_error=raise_error
        )
        return
    try:
        crl_response = requests.get(download_link)
        crl_response.raise_for_status()
    except (requests.HTTPError, requests.ConnectionError, requests.Timeout):
        if raise_error:
            raise
        return
    try:
        return load_x509_crl(crl_response.content)
    except ValueError:
        if raise_error:
            raise


def verify_against_crl(
    cert: x509.Certificate,
    raise_error: bool = True
) -> bool:
    crl = get_crl_from_cert(cert, raise_error)
    if not crl:
        # No CRL available, which we should treat the certificate as not
        # revoked
        return True
    revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    return not revoked


def check_revoke(
    cert: x509.Certificate,
    issuer: x509.Certificate
) -> typing.Optional[bool]:
    not_revoked = verify_against_ocsp(cert, issuer, raise_error=False)
    if not_revoked is None:
        logger.info("Failed to check against OCSP. Using CRL instead.")
        not_revoked = verify_against_crl(cert, raise_error=False)
    return not_revoked
