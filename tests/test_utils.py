from make_certificate_chain import utils

def test_get_system_ca():
    system_ca = utils.get_system_ca()
    assert len(system_ca) > 0
