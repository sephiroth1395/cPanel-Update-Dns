#!/usr/bin/env python3

##### Python cPanel DNS update
### Based on script from nikigre/cPanel-Update-Dns
### Updated by Eric Viseur <eric.viseur@gmail.com> to support fetching the 
### IP addresses from OPNsense API

### Imports

import base64
import argparse
from urllib.request import urlopen,Request
import json

### Get IP via external service
def fetch_external_ip():

    try:
        if(type == 'A'):
            url = 'https://api.ipify.org'
            ip = urlopen(url).read().decode('utf-8')        
        if(type == 'AAAA'):
            url = 'https://api64.ipify.org'
            ip = urlopen(url).read().decode('utf-8')
    
        if(args.verbose): print("INFO - Detected IP address: " + ip)
        return ip
    except:
        print('ERROR - Could not obtain IP address from ipify API.')
        exit(1)

### Get IP via local network interfaces
def fetch_interface_ip(itf):

    try:
        if(type == 'A'):
            ip = netifaces.ifaddresses(itf)[netifaces.AF_INET][0]['addr']
        elif(type == 'AAAA'):
            entries = netifaces.ifaddresses(itf)[netifaces.AF_INET6]
            for entry in entries:
                if('fe80' not in entry):
                    ip = entry['addr']
                    break

        if(args.verbose): print("INFO - Detected IP address: " + ip)
        return ip
    except:
        print('ERROR - Could not obtain IP address from local interface.')
        exit(1)

### Get IP via OPNsense API
def fetch_OPNsense(api_key = '', api_secret = '', opnsense_url = '', itf = ''):

    try:
        interface_client = diagnostics.InterfaceClient(api_key, api_secret, opnsense_url, verify_cert=False, timeout = 5)
    except:
        print('ERROR - Cannot connect to OPNsense API')
        exit(1)

    if(type == 'A'):
        arp_table = interface_client.get_arp()
        for entry in arp_table:
            if(entry['intf'] == itf) and (entry['permanent'] == True):
                address = entry['ip']        
    elif(type == 'AAAA'):
        ndp_table = interface_client.get_ndp()
        for entry in ndp_table:
            if(entry['intf'] == itf) and ('fe80' not in entry['ip']):
                address = entry['ip']

    if(address):
        if(args.verbose): print("INFO - Detected IP address: " + address)
        return address
    else:
        print('ERROR - Could not obtain IP address from OPNsense.')
        exit(1)

### Main routine

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    try:
        from config import CONFIG
    except ImportError:
        parser.add_argument('--username', help='cPanel username', required=True)
        parser.add_argument('--password', help='cPanel password', required=True)
        parser.add_argument('--url', help='URL to your cPanel', required=True)
        parser.add_argument('--opn_itf', help='OPNsense method only: the WAN interface (i.e. vtnet0)')
        parser.add_argument('--opn_url', help='OPNsense method only: the API url (i.e. http://192.168.0.1/api')
        parser.add_argument('--opn_key', help='OPNsense method only: the API key')
        parser.add_argument('--opn_secret', help='OPNsense method only: the API secret')

    # Show all arguments
    parser.add_argument('--ttl', default='3600', help='Time To Live')
    parser.add_argument('-t', '--type', default='A', help='Type of record: A for IPV4 or AAAA for IPV6')
    parser.add_argument('-m', '--method', default='argument', help='The method to obtain the IP address', 
                        choices=['args', 'online', 'opnsense', 'interface'], required=True)
    parser.add_argument('--ip', help='The IPV4/IPV6 address when using the args method')
    parser.add_argument('--itf', help='The interface to poll when using the interface method')
    parser.add_argument('-n', '--name', help='Your record name, ie: ipv6.domain.com', required=True)
    parser.add_argument('-d', '--domain', help='The domain name containing the record name', required=True)
    parser.add_argument('-v', '--verbose', help='Display extra information.  If not set only errors are printed', action='store_true')
    args = parser.parse_args()

    if "CONFIG" in locals():
        args.username = CONFIG['username']
        args.password = CONFIG['password']
        args.url = CONFIG['url']
        if (args.method == 'opnsense'):
            args.opn_itf = CONFIG['opn_itf']
            args.opn_url = CONFIG['opn_url']
            args.opn_key = CONFIG['opn_key']
            args.opn_secret = CONFIG['opn_secret']

    # Generate a auth_string to connect to cPanel
    auth_string = 'Basic ' + base64.b64encode((args.username+':'+args.password).encode()).decode("utf-8")

    domain = args.domain
    record = args.name
    if not record.endswith('.'):
        record += "."
    
    type = args.type.upper()

    # Obtain the IP address
    if(args.verbose): print("Obtaining IP address for record " + type + " using method " + args.method)

    if (args.method == 'arguments'):
        ip = args.ip
    elif(args.method == 'online'):
        ip = fetch_external_ip()
    elif(args.method == 'interface'):
        import netifaces
        ip = fetch_interface_ip(args.itf)
    elif(args.method == 'opnsense'):
        from pyopnsense import diagnostics
        ip = fetch_OPNsense(args.opn_key, args.opn_secret, args.opn_url, args.opn_itf)
    else:
        print('ERROR - Unexpected IP extraction method.')
        exit(1)

    ttl = args.ttl

    # Fetch existing DNS records
    q = Request(args.url + '/json-api/cpanel?cpanel_jsonapi_module=ZoneEdit&cpanel_jsonapi_func=fetchzone&cpanel_jsonapi_apiversion=2&domain=' + domain)
    q.add_header('Authorization', auth_string)
    xml = urlopen(q).read().decode("utf-8")

    # Parse the records to find if the record already exists
    root = json.loads(xml)

    line = "0"
    ipFromDNS = ""

    records = root["cpanelresult"]["data"][0]["record"]

    for i in range(0, len(records)):
        if "name" in records[i]:
            if (records[i]["name"] == record) and (records[i]["type"] == type):
                line = records[i]["line"]
                ipFromDNS = records[i]["record"]
                break

    if (ipFromDNS == ip):
        if(args.verbose):
            print("INFO - The same IP is already set! Exiting.")
        exit(0)

    # Update or add the record
    query = "&address=" + ip

    url = args.url + "/json-api/cpanel?cpanel_jsonapi_module=ZoneEdit&cpanel_jsonapi_func=" + ("add" if line == "0" else "edit") + "_zone_record&cpanel_jsonapi_apiversion=2&domain="+ domain + "&name=" + record + "&type=" + type + "&ttl=" + ttl + query
    if line != "0":
        url += "&Line=" + str(line)

    if (args.verbose):
        print("INFO - URL sent to the server: " + url)
    
    q = Request(url)
    q.add_header('Authorization', auth_string)
    a = urlopen(q).read().decode("utf-8")

    answer = a.replace('\n', ' ')
    root = json.loads(answer)
    
    result = root['cpanelresult']['data'][0]['result']

    if (args.verbose):
        print("INFO - Response from the server: ")
        print(result)

    if (result['status'] != 1):
        print("ERROR - Could not update cPanel DNS record.")
        exit(1)

    exit(0)