from make_certificate_chain import utils
from make_certificate_chain import solver

def test_get_system_ca():
    system_ca = utils.get_system_ca()
    assert len(system_ca) > 0


def test_ocsp(example_com_cert: bytes):
    cert = utils.read_x509_certificates(example_com_cert)[0]
    issuer = solver.get_issuer_certificate(cert)[
        cert.issuer.rfc4514_string()][0]

    utils.verify_against_ocsp(cert, issuer)
