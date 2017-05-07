""" Here is the base provider list with class """
### DNSBL CATEGORIES ###
# providers answers could be interpreted in one of the following categories
DNSBL_CATEGORIES = ['spam', 'proxy', 'malware', 'botnet', 'exploits', 'unknown']

class Provider(object):

    def __init__(self, host):
        self.host = host

    def process_result(self, results):
        """ 
        Usually DNSBL lists returns ip-codes like this: 127.0.0.2
        Some of the lists provides some additional specification about
        this codes and their meaning. This function is helpful to build mapping 
        between response codes and DNSBL_CATEGORIES.  It is used in construction
        if DNSBLResult from DNSBLChecker. You should redefine this function
        in your custom providers.
        
        Parmeters:
            result - list of ares dns responses

        Returns:
            set of categories (DNSBL_CATEGORIES subset)

        """
        return set(['unknown']) 

    def __repr__(self):
        return "<Provider: %s>" % self.host

class ZenSpamhaus(Provider):
    """ Combined spamhaus list:
        https://www.spamhaus.org/faq/section/DNSBL%20Usage#200
    """

    def __init__(self):
        self.host = 'zen.spamhaus.org'

    def process_result(self, results):
        categories = set() 
        for result in results:
            if result.host in ['127.0.0.2', '127.0.0.3', '127.0.0.9']:
                categories.add('spam')
            if result.host in ['127.0.0.4', '127.0.0.5', '127.0.0.6', '127.0.0.7']:
                categories.add('exploits')
        return categories
            

# this list is converted into list of Providers bellow
_BASE_PROVIDERS = [
    'aspews.ext.sorbs.net',
    'b.barracudacentral.org',
    'bl.deadbeef.com',
    'bl.emailbasura.org',
    'bl.spamcannibal.org',
    'bl.spamcop.net',
    'blackholes.five-ten-sg.com',
    'blacklist.woody.ch',
    'bogons.cymru.com',
    'cbl.abuseat.org',
    'cdl.anti-spam.org.cn',
    'combined.abuse.ch',
    'combined.rbl.msrbl.net',
    'db.wpbl.info',
    'dnsbl-1.uceprotect.net',
    'dnsbl-2.uceprotect.net',
    'dnsbl-3.uceprotect.net',
    'dnsbl.cyberlogic.net',
    'dnsbl.inps.de',
    'dnsbl.sorbs.net',
    'drone.abuse.ch',
    'duinv.aupads.org',
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
    'orvedb.aupads.org',
    'phishing.rbl.msrbl.net',
    'proxy.bl.gweep.ca',
    'proxy.block.transip.nl',
    'psbl.surriel.com',
    'rbl.interserver.net',
    'relays.bl.gweep.ca',
    'relays.bl.kundenserver.de',
    'relays.nether.net',
    'residential.block.transip.nl',
    'short.rbl.jp',
    'smtp.dnsbl.sorbs.net',
    'socks.dnsbl.sorbs.net',
    'spam.abuse.ch',
    'spam.dnsbl.sorbs.net',
    'spam.rbl.msrbl.net',
    'spam.spamrats.com',
    'spamlist.or.kr',
    'spamrbl.imp.ch',
    'tor.dnsbl.sectoor.de',
    'torserver.tor.dnsbl.sectoor.de',
    'ubl.lashback.com',
    'ubl.unsubscore.com',
    'virbl.bit.nl',
    'virus.rbl.jp',
    'virus.rbl.msrbl.net',
    'web.dnsbl.sorbs.net',
    'wormrbl.imp.ch',
    'zombie.dnsbl.sorbs.net',
]

BASE_PROVIDERS = [Provider(host) for host in _BASE_PROVIDERS] + [ZenSpamhaus()]
