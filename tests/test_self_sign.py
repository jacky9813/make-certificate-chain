import datetime

from cryptography import x509
import pytest

import make_certificate_chain.solver
import make_certificate_chain.warnings


def test_self_sign(self_sign_cert: x509.Certificate):
    with pytest.warns((
        make_certificate_chain.warnings.SelfSignCertificateWarning,
        make_certificate_chain.warnings.NearExpirationWarning
    )):
        response = list(make_certificate_chain.solver.solve_cert_chain(
            self_sign_cert,
            expire_warning=datetime.timedelta(days=15)
        ))
    assert response == [self_sign_cert]


