import asyncio
import threading

import pytest
from .checker import DNSBLChecker, DNSBLIpChecker, DNSBLDomainChecker
from .providers import Provider

# IP TESTS
def test_checker():
    checker = DNSBLIpChecker()
    res = checker.check('68.128.212.240')
    assert res.blacklisted
    assert res.categories
    assert res.detected_by
    results = checker.bulk_check(['68.128.212.240', '8.8.8.8'])
    # check bulk check
    assert results[0].detected_by == res.detected_by
    assert not results[1].blacklisted

def test_checker_ipv6():
    checker = DNSBLIpChecker()
    res = checker.check('2001:4860:4860::8844')
    assert not res.blacklisted
    assert not res.categories
    assert not res.detected_by
    assert not res.failed_providers
    checker = DNSBLIpChecker(providers=[Provider('v6.fullbogons.cymru.com')])
    res = checker.check('::1')
    assert res.blacklisted
    assert res.categories
    assert res.detected_by

def test_providers():
    """ Providers should not mark google ip as bad """
    checker = DNSBLIpChecker()
    res = checker.check('8.8.8.8')
    assert not res.blacklisted
    assert not res.categories
    assert not res.detected_by
    assert not res.failed_providers

def test_wrong_ip_format():
    misformated_ips = ['abc', '8.8.8.256']
    for ip in misformated_ips:
        checker = DNSBLIpChecker()
        with pytest.raises(ValueError):
             checker.check(ip)

# DOMAIN TESTS
def test_domain_checker():
    checker = DNSBLDomainChecker()
    malicious_domain = 'etoroinvestmentltd.com'
    res = checker.check(malicious_domain)
    assert res.blacklisted
    assert res.categories
    assert res.detected_by
    results = checker.bulk_check([malicious_domain, 'google.com'])
    # check bulk check
    assert results[0].detected_by == res.detected_by
    assert not results[1].blacklisted

def test_domain_idna():
    checker = DNSBLDomainChecker()
    res = checker.check('вуцхгйю.рф')
    assert res.blacklisted
    assert res.categories
    assert res.detected_by

def test_domain_providers():
    """ Domain Providers should not mark google.com as bad """
    checker = DNSBLDomainChecker()
    res = checker.check('google.com')
    assert not res.blacklisted
    assert not res.categories
    assert not res.detected_by
    assert not res.failed_providers

def test_wrong_domain_format():
    misformated_ips = ['abc-', '8.8.8.256']
    for ip in misformated_ips:
        checker = DNSBLDomainChecker()
        with pytest.raises(ValueError):
             print(checker.check(ip))

def test_capitalization_in_domain():
    capitalized_domains = ['Google.com', 'Facebook.com']
    for domain in capitalized_domains:
        checker = DNSBLDomainChecker()
        res = checker.check(domain)
        assert not res.blacklisted
        assert not res.categories
        assert not res.detected_by
        assert not res.failed_providers

# Threading tests
def test_main_thread():
    result = None
    def test():
        nonlocal result
        checker = DNSBLIpChecker()
        result = checker.check('68.128.212.240')
    thr = threading.Thread(target=test)
    thr.start()
    thr.join()
    assert result.blacklisted

## COMPAT TESTS
def test_checker_compat_0_6():
    checker = DNSBLChecker()
    res = checker.check_ip('68.128.212.240')
    assert res.blacklisted
    assert res.categories
    assert res.detected_by
    results = checker.check_ips(['68.128.212.240', '8.8.8.8'])
    # check bulk check
    assert results[0].detected_by == res.detected_by
    assert not results[1].blacklisted

def test_providers_compat_0_6():
    """ Providers should not mark google ip as bad """
    checker = DNSBLChecker()
    res = checker.check_ip('8.8.8.8')
    assert not res.blacklisted
    assert not res.categories
    assert not res.detected_by
    assert not res.failed_providers

def test_wrong_ip_format_compat_0_6():
    misformated_ips = ['abc', '8.8.8.256']
    for ip in misformated_ips:
        checker = DNSBLChecker()
        with pytest.raises(ValueError):
             checker.check_ip(ip)
