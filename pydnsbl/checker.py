import asyncio
import aiodns
import socket
from providers import BASE_PROVIDERS

class DNSBLResult(object):
    """ 
    DNSBL Result class to keep all info about ip request results.
    """
    def __init__(self, ip=None, results=None):
        self.ip = ip
        self._results = results
        self.providers = []
        self.detected_by = {} 
        self.categories = set()
        self.process_results()

    def process_results(self):
        """ Process results by providers """
        for provider, result in self._results:
            self.providers.append(provider)
            if not isinstance(result, list):
                continue

            provider_categories =  provider.process_result(result)
            self.categories = self.categories.union(provider_categories)
            self.detected_by[provider.host] = list(provider_categories)

    @property
    def blacklisted(self):
        if len(self.detected_by)>0:
            return True

    def __repr__(self):
        blacklisted = self.blacklisted and '[BLACKLISTED]' or ''
        return "<DNSBLResult: %s %s (%d/%d)>" % (self.ip, blacklisted, len(self.detected_by),
                                              len(self.providers))

class DNSBLChecker(object):
    """ 
    Checker for DNSBL lists 
    Arguments:
        providers - list of providers
        timeout - timeout of dns requests
        tries - retry times
    """

    def __init__(self, providers=BASE_PROVIDERS, timeout=5, tries=2):
        self.providers = BASE_PROVIDERS
        self.loop = asyncio.get_event_loop()
        self.resolver = aiodns.DNSResolver(timeout=timeout, tries=tries, loop=self.loop)

    async def dnsbl_request(self, ip, provider, fail_silently=True):
        """ 
        Make lookup to dnsbl provider
        Parameters:
            ip (string) - ip address to check
            provider (string) - dnsbl provider
            fail_silently (boolean) - when True then will not raise exception 
                                          if request fails (timeout etc)

        Returns:
            tuple (provider, answer) - answer could contain dns response of the 
                server, or None (if ip is not listed) in this DNSBL or DNSError 
                exception if request fails and fail_silently == True

        Raises:
            ValueError
        """
        try:
            socket.inet_aton(ip)
        except socket.error:
            raise ValueError('wrong ip format')
        ip_reversed = '.'.join(reversed(ip.split('.')))
        dnsbl_query = "%s.%s" % (ip_reversed, provider.host)
        try:
            answer = await self.resolver.query(dnsbl_query, 'A')
        except aiodns.error.DNSError as error:
            if error.args[0] == 4:
                # domain name not found:
                return provider, None
            else:
                if fail_silently:
                    return provider, None
                else:
                    return provider, error
        else:
            return provider, answer 

    def check_ip(self, ip):
        """ Check ip with dnsbl providers """

        tasks = []
        for provider in self.providers:
            tasks.append(self.dnsbl_request(ip, provider))
        results = self.loop.run_until_complete(asyncio.gather(*tasks))
        return DNSBLResult(ip=ip, results=results) 

    def check_providers(self, hide_good=False):
        """ 
        Check dnsbl availability. Utility function to test your providers. 
        
        Parameters:
            hide_good (boolean) - if True then only dnsbl with problems will be shown
        """
        ip = '8.8.8.8'
        tasks = []
        for provider in self.providers:
            tasks.append(self.dnsbl_request(ip, provider, fail_silently=False))
        responses = self.loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
        check_results = []
        for provider,result in responses:
            if result is None:
                # everything is ok, google ip should not be listed
                if hide_good:
                    continue
                check_result = 'ok'
            elif isinstance(result, aiodns.error.DNSError):
                check_result = 'request error'
            elif isinstance(result, list):
                # if google is listed this is a reason for additional check of the list
                check_result = 'warning! google is listed'
            check_results.append((provider, check_result))
        return check_results 


#checker = DNSBLChecker()
#res = checker.check_ip('68.128.212.240')
#res = checker.check_providers(hide_good=True)
#print(res)
#print(res.categories)
print(res.detected_by)
