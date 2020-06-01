"""
Place to define providers.
Most part of _BASE_PROVIDERS was taken from https://github.com/vincecarney/dnsbl
"""
### DNSBL CATEGORIES ###
# providers answers could be interpreted in one of the following categories
DNSBL_CATEGORY_UNKNOWN = 'unknown'
DNSBL_CATEGORY_SPAM = 'spam'
DNSBL_CATEGORY_EXPLOITS = 'exploits'
DNSBL_CATEGORY_PHISH = 'phish'
DNSBL_CATEGORY_MALWARE = 'malware'
DNSBL_CATEGORY_CNC = 'cnc'
DNSBL_CATEGORY_ABUSED = 'abused'
DNSBL_CATEGORY_LEGIT = 'legit'

class Provider(object):

    def __init__(self, host):
        self.host = host

    def process_response(self, response):
        """
        Usually DNSBL lists returns ip-codes like this: 127.0.0.2
        Some of the lists provides some specification about
        this codes and their meaning. This function will be helpful to build mapping
        between response codes and DNSBL_CATEGORIES.  It is used in construction
        of DNSBLResult. You should redefine this function
        in your custom providers according to their specification.

        Parmeters:
            result - list of c-ares dns responses

        Returns:
            set of categories (DNSBL_CATEGORIES subset)

        """
        result = set()
        if response:
            result.add(DNSBL_CATEGORY_UNKNOWN)
        return result

    def __repr__(self):
        return "<Provider: %s>" % self.host

class ZenSpamhaus(Provider):
    """ Combined spamhaus list:
        https://www.spamhaus.org/faq/section/DNSBL%20Usage#200
    """

    def __init__(self, host='zen.spamhaus.org'):
        Provider.__init__(self, host=host)

    def process_response(self, response):
        categories = set()
        for result in response:
            if result.host in ['127.0.0.2', '127.0.0.3', '127.0.0.9']:
                categories.add(DNSBL_CATEGORY_SPAM)
            elif result.host in ['127.0.0.4', '127.0.0.5', '127.0.0.6', '127.0.0.7']:
                categories.add(DNSBL_CATEGORY_EXPLOITS)
            else:
                categories.add(DNSBL_CATEGORY_UNKNOWN)
        return categories

# this list is converted into list of Providers bellow

_BASE_PROVIDERS = [
    'aspews.ext.sorbs.net',
    'b.barracudacentral.org',
    'bl.spamcop.net',
    'blackholes.five-ten-sg.com',
    'blacklist.woody.ch',
    'bogons.cymru.com',
    'cbl.abuseat.org',
    'combined.abuse.ch',
    'combined.rbl.msrbl.net',
    'db.wpbl.info',
    'dnsbl-2.uceprotect.net',
    'dnsbl-3.uceprotect.net',
    'dnsbl.cyberlogic.net',
    'dnsbl.sorbs.net',
    'drone.abuse.ch',
    'dul.dnsbl.sorbs.net',
    'dul.ru',
    'dyna.spamrats.com',
    'dynip.rothen.com',
    'http.dnsbl.sorbs.net'
    'images.rbl.msrbl.net',
    'ips.backscatterer.org',
    'ix.dnsbl.manitu.net',
    'korea.services.net',
    'misc.dnsbl.sorbs.net',
    'noptr.spamrats.com',
    'phishing.rbl.msrbl.net',
    'proxy.bl.gweep.ca',
    'proxy.block.transip.nl',
    'psbl.surriel.com',
    'rbl.interserver.net',
    'relays.bl.gweep.ca',
    'relays.bl.kundenserver.de',
    'relays.nether.net',
    'residential.block.transip.nl',
    'smtp.dnsbl.sorbs.net',
    'socks.dnsbl.sorbs.net',
    'spam.dnsbl.sorbs.net',
    'spam.rbl.msrbl.net',
    'spam.spamrats.com',
    'spamlist.or.kr',
    'spamrbl.imp.ch',
    'ubl.lashback.com',
    'ubl.unsubscore.com',
    'virbl.bit.nl',
    'virus.rbl.msrbl.net',
    'web.dnsbl.sorbs.net',
    'wormrbl.imp.ch',
    'zombie.dnsbl.sorbs.net',
]

class DblSpamhaus(Provider):
    """ Spamhaus domain blacklist
        https://www.spamhaus.org/faq/section/Spamhaus%20DBL#291
    """
    CATEGORY_MAPPING = {
        '127.0.1.2': {DNSBL_CATEGORY_SPAM},
        '127.0.1.4': {DNSBL_CATEGORY_PHISH},
        '127.0.1.5': {DNSBL_CATEGORY_MALWARE},
        '127.0.1.6': {DNSBL_CATEGORY_CNC},
        '127.0.1.102': {DNSBL_CATEGORY_ABUSED, DNSBL_CATEGORY_LEGIT, DNSBL_CATEGORY_SPAM},
        '127.0.1.103': {DNSBL_CATEGORY_ABUSED, DNSBL_CATEGORY_SPAM},
        '127.0.1.104': {DNSBL_CATEGORY_ABUSED, DNSBL_CATEGORY_LEGIT, DNSBL_CATEGORY_PHISH},
        '127.0.1.105': {DNSBL_CATEGORY_ABUSED, DNSBL_CATEGORY_LEGIT, DNSBL_CATEGORY_MALWARE},
        '127.0.1.106': {DNSBL_CATEGORY_ABUSED,  DNSBL_CATEGORY_LEGIT, DNSBL_CATEGORY_CNC}
    }

    def __init__(self, host='dbl.spamhaus.org'):
        Provider.__init__(self, host=host)

    def process_response(self, response):
        categories = set()
        for result in response:
            result_categories = self.CATEGORY_MAPPING.get(result.host, {DNSBL_CATEGORY_UNKNOWN})
            categories.update(result_categories)

        return categories

# list of domain providers
_DOMAIN_PROVIDERS = [
    'uribl.spameatingmonkey.net',
    'multi.surbl.org',
    'rhsbl.sorbs.net '
]

BASE_PROVIDERS = [Provider(host) for host in _BASE_PROVIDERS] + [ZenSpamhaus()]
BASE_DOMAIN_PROVIDERS = [Provider(host) for host in _DOMAIN_PROVIDERS] + [DblSpamhaus()]
