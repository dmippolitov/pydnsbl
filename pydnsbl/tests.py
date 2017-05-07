from .checker import DNSBLChecker

def test_checker():
    checker = DNSBLChecker()
    res = checker.check_ip('68.128.212.240')
    assert res.blacklisted
    assert res.categories
    assert res.detected_by

def test_providers():
    """ Providers should not mark google ip as bad """
    checker = DNSBLChecker()
    res = checker.check_ip('8.8.8.8')
    assert not res.blacklisted
    assert not res.categories
    assert not res.detected_by
    print(res.failed_providers)
    assert not res.failed_providers
