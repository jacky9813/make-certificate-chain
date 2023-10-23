import pytest

from cryptography import x509

import make_certificate_chain.solver
import make_certificate_chain.exceptions


def test_unknown_ca(cert_with_unknown_ca: x509.Certificate):
    with pytest.raises(make_certificate_chain.exceptions.NoIssuerCertificateError):
        list(make_certificate_chain.solver.solve_cert_chain(cert_with_unknown_ca))


def test_expired(self_sign_cert_expired: x509.Certificate):
    with pytest.raises(make_certificate_chain.exceptions.CertificateExpiredError):
        list(make_certificate_chain.solver.solve_cert_chain(self_sign_cert_expired))