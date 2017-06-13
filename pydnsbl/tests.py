from .checker import DNSBLChecker

def test_checker():
    checker = DNSBLChecker()
    res = checker.check_ip('68.128.212.240')
    assert res.blacklisted
    assert res.categories
    assert res.detected_by
    results = checker.check_ips(['68.128.212.240', '8.8.8.8'])
    # check bulk insert
    assert results[0].detected_by == res.detected_by
    assert not results[1].blacklisted

def test_providers():
    """ Providers should not mark google ip as bad """
    checker = DNSBLChecker()
    res = checker.check_ip('8.8.8.8')
    assert not res.blacklisted
    assert not res.categories
    assert not res.detected_by
    print(res.failed_providers)
    assert not res.failed_providers
