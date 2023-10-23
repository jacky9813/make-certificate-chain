import typing
import os
import ssl
import sys
import getpass

import cryptography.x509
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives.serialization import pkcs12

CERTIFICATE_BEGIN = "-----BEGIN CERTIFICATE-----"
PKCS7_BEGIN = "-----BEGIN PKCS7-----"

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
    if sys.platform == "win32":
        ca_list = [
            cryptography.x509.load_der_x509_certificate(ca_info[0])
            for ca_info in ssl.enum_certificates("root")
        ]
    else:
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


def read_x509_certificate(
    raw_data: bytes
) -> typing.List[cryptography.x509.Certificate]:
    if CERTIFICATE_BEGIN.encode() in raw_data:
        return [cryptography.x509.load_pem_x509_certificate(raw_data)]
    return [cryptography.x509.load_der_x509_certificate(raw_data)]


def read_pkcs7_certificates(
    raw_data: bytes
) -> typing.List[cryptography.x509.Certificate]:
    if PKCS7_BEGIN.encode() in raw_data:
        return pkcs7.load_pem_pkcs7_certificates(raw_data)
    return pkcs7.load_der_pkcs7_certificates(raw_data)
    
def read_pkcs12_certificates(
    raw_data: bytes,
    password: typing.Optional[bytes] = None
) -> typing.List[cryptography.x509.Certificate]:
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
