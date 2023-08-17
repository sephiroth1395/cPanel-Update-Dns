# cPanel-Update-Dns
Python 3 script to update IPV4/IPV6 dynamic IP to cPanel DNS records

This script supports four different methods to get the IP address:
 * Via a command-line argument (args)
 * By reading the IP address on a local network interface (interface)
 * Using the onlien apify API (online)
 * Using the OPNsense API to read the IP addresses of a provided interface (opnsense)

## Requirements

 * This script requires the `base64`, `argparse`, `urllib` and `json` Python packages.
 * The *interface* method requires `netifaces`.
 * The *opnsense* method requires `pyopnsense`.

## Configuration
Need a config.py file containing your cPanel credentials :

```python
CONFIG = {
    'username': 'USERNAME HERE',
    'password': 'PASSWORD HERE',
    'url': 'https://DOMAIN.COM:2083'
}
```

## Using the OPNsense API
On your OPNsense gateway, under _System_ > _Access_ > _Users_, create a dedicated user
 * Scrambled password
 * Privileges *Diagnostics: ARP Table* and *Diagnostics NDP Table* are sufficient
 * Create an API key and store it in a safe place (i.e. BitWarden or KeePass)

In the `config.py` file, add the following extra fields:
```python
    'opn_key': 'YOUR API KEY',
    'opn_secret': 'YOUR API SECRET',
    'opn_url': 'YOUR GATEWAY URL, TRAILING WITH /api',
    'opn_itf': 'YOUR WAN PHYSICAL INTERFACE'
```

## Usage
Elements from `config.py` can also be passed as arguments, but this is not recommended.

```shell

usage: updatedns.py [-h] [--ttl TTL] [-t TYPE] -m {args,online,opnsense,interface} [--ip IP] [--itf ITF] -n NAME -d DOMAIN [-v]

optional arguments:
  -h, --help            show this help message and exit
  --ttl TTL             Time To Live
  -t TYPE, --type TYPE  Type of record: A for IPV4 or AAAA for IPV6
  -m {args,online,opnsense,interface}, --method {args,online,opnsense,interface}
                        The method to obtain the IP address
  --ip IP               The IPV4/IPV6 address when using the args method
  --itf ITF             The interface to poll when using the interface method
  -n NAME, --name NAME  Your record name, ie: ipv6.domain.com
  -d DOMAIN, --domain DOMAIN
                        The domain name containing the record name
  -v, --verbose         Display extra information. If not set only errors are printed

  ```