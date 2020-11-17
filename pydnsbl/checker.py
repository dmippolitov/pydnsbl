"""
DNSBL async checker
Basic usage:
    checker = DNSBLChecker()
    result = cheker.check_ip('...')
    print(result.blacklisted)
    print(result.categories)
    print(result.detected_by)
"""
import abc
import asyncio
import idna
import ipaddress
import re
import sys
import threading
import warnings

import aiodns

from .providers import Provider, BASE_PROVIDERS, BASE_DOMAIN_PROVIDERS

if sys.platform == 'win32' and sys.version_info >= (3, 8):
    # fixes https://github.com/dmippolitov/pydnsbl/issues/12
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

class DNSBLResult:
    """
    DNSBL Result class to keep all info about ip request results.

    Attributes:
        * addr - checked ip
        * providers - dnsbl that was asked for response while checking
        * failed_provider - dnsbl that was unable to provide result due
            to connection issues (connection timeout etc...)
        * detected_by - dnsbl that have ip listed and categories detected by
            this dnsbls. dict: {'dnsbl_list_name': list(categories_from_this_dnsbl)}
        * categories - set of dnsbl categories from all providers (subset of DNSBL_CATEGORIES)
    """
    def __init__(self, addr=None, results=None):
        self.addr = addr
        self._results = results
        self.blacklisted = False
        self.providers = []
        self.failed_providers = []
        self.detected_by = {}
        self.categories = set()
        self.process_results()

    def process_results(self):
        """ Process results by providers """
        for result in self._results:
            provider = result.provider
            self.providers.append(provider)
            if result.error:
                self.failed_providers.append(provider)
                continue
            if not result.response:
                continue
            # set blacklisted to True if ip is detected with at least one dnsbl
            self.blacklisted = True
            provider_categories = provider.process_response(result.response)
            self.categories = self.categories.union(provider_categories)
            self.detected_by[provider.host] = list(provider_categories)

    def __repr__(self):
        blacklisted = '[BLACKLISTED]' if self.blacklisted else ''
        return "<DNSBLResult: %s %s (%d/%d)>" % (self.addr, blacklisted, len(self.detected_by),
                                                 len(self.providers))

class DNSBLResponse:
    """
    DNSBL Response object
    """
    def __init__(self, addr=None, provider=None, response=None, error=None):
        self.addr = addr
        self.provider = provider
        self.response = response
        self.error = error

class BaseDNSBLChecker(abc.ABC):
    """ BASE Checker for DNSBL lists
        Arguments:
            * providers(list) - list of providers (Provider instance or str)
            * timeout(int) - timeout of dns requests will be passed to resolver
            * tries(int) - retry times
    """

    def __init__(self, providers=BASE_PROVIDERS, timeout=5,
                 tries=2, concurrency=200, loop=None):
        self.providers = []
        for provider in providers:
            if not isinstance(provider, Provider):
                raise ValueError('providers should contain only Provider instances')
            self.providers.append(provider)
        if not loop:
            if threading.current_thread() == threading.main_thread():
                self._loop = asyncio.get_event_loop()
            else:
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
        else:
            self._loop = loop
        self._resolver = aiodns.DNSResolver(timeout=timeout, tries=tries, loop=self._loop)
        self._semaphore = asyncio.Semaphore(concurrency)


    async def dnsbl_request(self, request, provider):
        """
        Make lookup to dnsbl provider for ip
        Parameters:
            * addr (string) - ip address to check
            * provider (string) - dnsbl provider

        Returns:
            * DNSBLResponse object

        Raises:
            * ValueError
        """
        response = None
        error = None
        dnsbl_query = "%s.%s" % (self.prepare_query(request), provider.host)
        try:
            async with self._semaphore:
                response = await self._resolver.query(dnsbl_query, 'A')
        except aiodns.error.DNSError as exc:
            if exc.args[0] != 4: # 4: domain name not found:
                error = exc

        return DNSBLResponse(addr=request, provider=provider, response=response, error=error)

    @abc.abstractmethod
    def prepare_query(self, request):
        """
        Prepare query to dnsbl
        """
        return NotImplemented

    async def check_async(self, request):
        tasks = []
        for provider in self.providers:
            tasks.append(self.dnsbl_request(request, provider))
        results = await asyncio.gather(*tasks)
        return DNSBLResult(addr=request, results=results)

    def check(self, request):
        return self._loop.run_until_complete(self.check_async(request))

    def bulk_check(self, requests):
        tasks = []
        for request in requests:
            tasks.append(self.check_async(request))
        return self._loop.run_until_complete(asyncio.gather(*tasks))


class DNSBLIpChecker(BaseDNSBLChecker):
    """
    Checker for ips
    """
    def prepare_query(self, request):
        address = ipaddress.ip_address(request)
        if address.version == 4:
            return '.'.join(reversed(request.split('.')))
        elif address.version == 6:
            # according to RFC: https://tools.ietf.org/html/rfc5782#section-2.4
            request_stripped = request.replace(':', '')
            return '.'.join(reversed([x for x in request_stripped]))
        else:
            raise ValueError('unknown ip version')




class DNSBLDomainChecker(BaseDNSBLChecker):
    """
    Checker for domains
    """

    # regex taken from https://regexr.com/3abjr
    DOMAIN_REGEX = re.compile(r"^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$")

    def __init__(self, providers=BASE_DOMAIN_PROVIDERS, timeout=5,
                 tries=2, concurrency=200, loop=None):
        super().__init__(providers=providers, timeout=timeout,
                 tries=tries, concurrency=concurrency, loop=loop)

    def prepare_query(self, request):
        request = request.lower() # Adding support for capitalized letters in domain name.
        domain_idna = idna.encode(request).decode()
        if not self.DOMAIN_REGEX.match(domain_idna):
            raise ValueError('should be valid domain, got %s' % domain_idna)
        return domain_idna

# COMPAT
class DNSBLChecker(DNSBLIpChecker):
    """
    Will be deprecated, use DNSBLIpChecker
    """
    def __init__(self, *args, **kwargs):
        warnings.warn('deprecated, use DNSBLIpChecker', DeprecationWarning)
        super().__init__(*args, **kwargs)

    def check_ip(self, addr):
        warnings.warn('deprecated, use check method instead', DeprecationWarning)
        return self.check(addr)

    def check_ips(self, addrs):
        warnings.warn('deprecated, use bulk check method instead', DeprecationWarning)
        return self.bulk_check(addrs)
