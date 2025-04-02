import typing

from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.x509 import ocsp

class CertificateExpiredError(Exception):
    pass

class NoIssuerCertificateError(Exception):
    pass

class OCSPVerificationFailed(Exception):
    def __init__(
        self,
        *args,
        cert: x509.Certificate,
        ocsp_source: str,
        ocsp_response: typing.Optional[ocsp.OCSPResponse],
        **kwargs
    ):
        if not isinstance(cert, x509.Certificate):
            raise TypeError(
                "cert must be an instnace of cryptography.x509.Certificate"
            )
        if not isinstance(ocsp_source, str):
            raise TypeError(
                "ocsp_source must be a str"
            )
        if (
            not isinstance(ocsp_response, ocsp.OCSPResponse) and
            ocsp_response is not None
        ):
            raise TypeError(
                "oscp_response must be None or an instnace of "
                "cryptography.x509.ocsp.OCSPResponse"
            )
        super().__init__(*args, **kwargs)
        self.cert = cert
        self.ocsp_source = ocsp_source
        self.ocsp_response = ocsp_response

    def __str__(self) -> str:
        if self.ocsp_response:
            if self.ocsp_response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                return (
                    f'OCSP service {self.ocsp_source} responded with status '
                    f'{self.ocsp_response.certificate_status.name} on '
                    f'certificate {self.cert.subject.rfc4514_string()}'
                )
            else:
                return (
                    f'Failed to query OCSP service {self.ocsp_source} on '
                    f'certificate {self.cert.subject.rfc4514_string()}. '
                    f'Responded with {self.ocsp_response.response_status.name} '
                    f'status.'
                )
        return (
            f'OCSP service {self.ocsp_source} failed to respond with valid '
            f'OCSP response on certificate {self.cert.subject.rfc4514_string()}'
        )
