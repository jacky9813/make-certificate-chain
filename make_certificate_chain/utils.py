import typing
import itertools
import glob
import os
import ssl
import sys
import getpass

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives.serialization import pkcs12


CERTIFICATE_BEGIN = "-----BEGIN CERTIFICATE-----"
PKCS7_BEGIN = "-----BEGIN PKCS7-----"


def read_x509_certificate(
    raw_data: bytes
) -> typing.List[x509.Certificate]:
    if CERTIFICATE_BEGIN.encode() in raw_data:
        return [x509.load_pem_x509_certificate(raw_data)]
    return [x509.load_der_x509_certificate(raw_data)]


def read_pkcs7_certificates(
    raw_data: bytes
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
        password or getpass.getpass(prompt="PKCS#12 password: ").strip().encode()
    )
    # If there's no key in the PKCS#12, parsed_p12.cert will be None
    return [
        parsed_p12.cert.certificate
    ] if parsed_p12.cert else [
        p12_cert.certificate
        for p12_cert in parsed_p12.additional_certs
    ]


SUPPORTED_FORMATS: typing.Dict[
    str,
    typing.Callable[[bytes], typing.List[x509.Certificate]]
] = {
    "x509": read_x509_certificate,
    "pkcs7": read_pkcs7_certificates,
    "pkcs12": read_pkcs12_certificates
}


def read_certificate_file(path: str, cert_fmt: str = "x509") -> typing.List[x509.Certificate]:
    with open(path, mode="rb") as cert_fd:
        certs = SUPPORTED_FORMATS[cert_fmt](cert_fd.read())
    return certs


def get_system_ca(
    path = None
) -> typing.Dict[str, typing.List[x509.Certificate]]:
    """
        Get the certificates from the system's CA list.
    """
    if sys.platform == "win32":
        ca_list = [
            x509.load_der_x509_certificate(ca_info[0])
            for ca_info in ssl.enum_certificates("root")
        ]
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
