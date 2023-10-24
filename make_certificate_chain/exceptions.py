from cryptography.exceptions import InvalidSignature

class CertificateExpiredError(Exception):
    pass

class NoIssuerCertificateError(Exception):
    pass
