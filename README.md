# Pydnsbl

Async [dnsbl](https://en.wikipedia.org/wiki/DNSBL) lists checker based
on asyncio/aiodns. Checks if ip is listed in anti-spam dns blacklists.
Multiple dns blacklists supported. Use aiodns for async dns requests.
Usually ip check run for 50+ lists takes less than one second. Also allow to check domains.

## Installation

`pip intall pydnsbl`

## Requirements

- python >= 3.5
- aiodns

## Usage
### Check ip
```
>>> import pydnsbl
>>> ip_checker = pydnsbl.DNSBLIpChecker()
>>> ip_checker.check('8.8.8.8')
<DNSBLResult: 8.8.8.8  (0/52)>
>>> ip_checker.check('68.128.212.240')
<DNSBLResult: 68.128.212.240 [BLACKLISTED] (6/52)>
```
### Check domain
```
>>> import pydnsbl
>>> domain_checker = pydnsbl.DNSBLDomainChecker()
>>> domain_checker.check('google.com')
<DNSBLResult: google.com  (0/4)>
>>> domain_checker.check('belonging708-info.xyz')
<DNSBLResult: belonging708-info.xyz [BLACKLISTED] (2/4)>
```

### DNSBLResult properties
- `DNSBLResult.addr` - ip address or domain that was checked
- `DNSBLResult.blacklisted` - boolean, True if ip/domain detected by at least one provider
- `DNSBLResult.detected_by` - dictionary containing providers hosts detected this ip/domain as keys and 
their category verdicts
- `DNSBLResult.categories` - combined categories from all providers for this ip/domain
- `DNSBLResult.providers` - list of providers that was performing the check
- `DNSBLResult.failed_providers` - list of providers that was unable to check this ip properly (possibly provider was down)

```
>>> result = domain_checker.check('belonging708-info.xyz')
>>> result.addr
'belonging708-info.xyz'
>>> result.blacklisted
True
>>> result.detected_by
{'multi.surbl.org': ['unknown'], 'dbl.spamhaus.org': ['spam']}
>>> result.categories
{'unknown', 'spam'}
>>> result.providers
[<Provider: uribl.spameatingmonkey.net>, <Provider: multi.surbl.org>, <Provider: rhsbl.sorbs.net >, <Provider: dbl.spamhaus.org>]
>>> result.failed_providers
[]

```

## Extending/overriding providers

### Basic

```python
 
from pydnsbl import DNSBLIpChecker, providers
from pydnsbl.providers import BASE_PROVIDERS, Provider
providers = BASE_PROVIDERS + [Provider('yourprovider1.com'), ...]
checker = DNSBLIpChecker(providers=providers)
```

### Advanced

Take a look into providers.py file.

-   Use **Provider** class to create your custom providers.
-   Override **process_response** method of **Provider** class to map
    providers response codes (127.0.0.x) to DNSBL categories.

Contact
-------

Feel free to contact me: ippolitov87 at gmail.com