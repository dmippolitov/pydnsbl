"""
DNSBL async checker
Basic usage:
    checker = DNSBLChecker()
    result = cheker.check_ip('...')
    print(result.blacklisted)
    print(result.categories)
    print(result.detected_by)
"""

import socket
import asyncio
import aiodns
from .providers import Provider, BASE_PROVIDERS, DNSBL_CATEGORIES

class DNSBLResult(object):
    """
    DNSBL Result class to keep all info about ip request results.

    Attributes:
        * ip - checked ip
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
            assert provider_categories.issubset(DNSBL_CATEGORIES)
            self.categories = self.categories.union(provider_categories)
            self.detected_by[provider.host] = list(provider_categories)

    def __repr__(self):
        blacklisted = '[BLACKLISTED]' if self.blacklisted else ''
        return "<DNSBLResult: %s %s (%d/%d)>" % (self.addr, blacklisted, len(self.detected_by),
                                                 len(self.providers))

class DNSBLResponse(object):
    """
    DNSBL Response object
    """
    def __init__(self, addr=None, provider=None, response=None, error=None):
        self.addr = addr
        self.provider = provider
        self.response = response
        self.error = error

class DNSBLChecker(object):
    """ Checker for DNSBL lists
        Arguments:
            * providers(list) - list of providers (Provider instance or str)
            * timeout(int) - timeout of dns requests will be passed to resolver
            * tries(int) - retry times
    """

    def __init__(self, providers=BASE_PROVIDERS, timeout=5, tries=2):
        self.providers = []
        for provider in providers:
            if not isinstance(provider, Provider):
                provider = Provider(host=provider)
            self.providers.append(provider)
        self.loop = asyncio.get_event_loop()
        self.resolver = aiodns.DNSResolver(timeout=timeout, tries=tries, loop=self.loop)

    async def dnsbl_request(self, addr, provider):
        """
        Make lookup to dnsbl provider
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
        try:
            socket.inet_aton(addr)
        except socket.error:
            raise ValueError('wrong ip format')
        ip_reversed = '.'.join(reversed(addr.split('.')))
        dnsbl_query = "%s.%s" % (ip_reversed, provider.host)
        try:
            response = await self.resolver.query(dnsbl_query, 'A')
        except aiodns.error.DNSError as exc:
            if exc.args[0] != 4: # 4: domain name not found:
                error = exc

        return DNSBLResponse(addr=addr, provider=provider, response=response, error=error)

    def check_ip(self, addr):
        """
        Check ip with dnsbl providers.
        Parameters:
            * addr - ip address to check

        Returns:
            * DNSBLResult object
        """

        tasks = []
        for provider in self.providers:
            tasks.append(self.dnsbl_request(addr, provider))
        results = self.loop.run_until_complete(asyncio.gather(*tasks))
        return DNSBLResult(addr=addr, results=results)
