Pydnsbl
===============
Async `dnsbl <https://en.wikipedia.org/wiki/DNSBL>`_ lists checker based on asyncio/aiodns. Checks if ip is listed in anti-spam dns blacklists. Multiple dns blacklists supported. Use aiodns for async dns requests. Usually ip check run for 60+ lists takes less than one second.

Installation
----------------
pip intall pydnsbl

Requirements
----------------
python >= 3.5, aiodns

Usage
------------------
>>> from pydnsbl import DNSBLChecker
>>> checker = DNSBLChecker()
>>> result = checker.check_ip('8.8.8.8')
>>> result
<DNSBLResult: 8.8.8.8  (0/62)> # google is clean
>>> result = checker.check_ip('68.128.212.240') 
>>> result
<DNSBLResult: 68.128.212.240 [BLACKLISTED] (12/62)>  # this is just for example
>>> result.blacklisted
True
# detected_by dnsbl providers and their category tag for this ip
>>> result.detected_by 
{'web.dnsbl.sorbs.net': ['unknown'], ...
'zen.spamhaus.org': ['spam', 'exploits']}


Extending/overriding providers
-------------------------------
Basic 
^^^^^^^^^^^^^^^^^^^^^
>>> from pydnsbl import DNSBLChecker
>>> providers = BASE_PROVIDERS + ['yourprovider1.com', ...]
>>> checker = DNSBLChecker(providers=providers)
# in providers parameter you can pass providers dnsbl host or Provider class object (see Advanced topic below)

Advanced
^^^^^^^^^^^^^^^^^^^^^
Take a look into providers.py file. Use **Provider** class to create your custom providers. Override **process_response** method of **Provider** class to map providers response codes (127.0.0.x) to DNSBLChecker categories. 

Contact
------------------
Feel free to contact me:  ippolitov87 at gmail.com
