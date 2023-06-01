from cryptography import x509

from make_certificate_chain import solver


def test_simple(example_com_cert: x509.Certificate):
    chain = solver.solve_cert_chain(example_com_cert, include_root_ca=True)
    assert len(chain) > 0


def test_pkcs7(epki_com_tw_cert: x509.Certificate):
    chain = solver.solve_cert_chain(epki_com_tw_cert, include_root_ca=False)
    assert len(chain) > 0
