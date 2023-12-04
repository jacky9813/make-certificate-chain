import typing
import itertools
import glob
import os
import ssl
import sys
import getpass
import subprocess
import re

import certifi
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes


CERTIFICATE_BEGIN = "-----BEGIN CERTIFICATE-----"
CERTIFICATE_RE = re.compile(
    r"((?:-{5}BEGIN CERTIFICATE-{5})[0-9a-zA-Z+/=\r\n]+(?:-{5}END CERTIFICATE-{5}))",
    re.DEBUG
)
PKCS7_BEGIN = "-----BEGIN PKCS7-----"

CertificateList = typing.Dict[str, typing.List[x509.Certificate]]


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
        password or getpass.getpass(prompt="PKCS#12 password: ").strip().encode()
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
    typing.Callable[[bytes, typing.Optional[bytes]], typing.List[x509.Certificate]]
] = {
    "x509": read_x509_certificates,
    "pkcs7": read_pkcs7_certificates,
    "pkcs12": read_pkcs12_certificates
}


def read_pkcs12_key(
    pkcs12_raw: bytes,
    password: typing.Optional[bytes] = None
) -> typing.Optional[PrivateKeyTypes]:
    parsed_p12 = pkcs12.load_pkcs12(pkcs12_raw,password)
    return parsed_p12.key


def read_certificate_file(path: str, cert_fmt: str = "x509") -> typing.List[x509.Certificate]:
    with open(path, mode="rb") as cert_fd:
        certs = CERTIFICATE_FORMATS[cert_fmt](cert_fd.read())
    return certs


def get_system_ca(
    path = None
) -> CertificateList:
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
