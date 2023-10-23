from cryptography import x509

from make_certificate_chain import solver
from make_certificate_chain import utils


def test_simple(example_com_cert: bytes):
    cert = utils.read_x509_certificate(example_com_cert)
    chain = list(solver.solve_cert_chain(cert[0], include_root_ca=True))
    assert len(chain) > 0
    sans = [
        san.value
        for san in chain[0].extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    ]
    assert "www.example.com" in sans


def test_pkcs7(epki_com_tw_cert: bytes):
    certs = utils.read_pkcs7_certificates(epki_com_tw_cert)
    chain = list(solver.solve_cert_chain(certs[0], include_root_ca=False))
    assert len(chain) > 0
    sans = [
        san.value
        for san in chain[0].extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    ]
    assert "epki.com.tw" in sans


def test_pkcs12(example_com_cert_pkcs12: bytes):
    certs = utils.read_pkcs12_certificates(
        example_com_cert_pkcs12,
        b'12345678'
    )
    chain = list(solver.solve_cert_chain(certs[0], include_root_ca=False))
    assert len(chain) > 0
    sans = [
        san.value
        for san in chain[0].extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    ]
    assert "www.example.com" in sans
