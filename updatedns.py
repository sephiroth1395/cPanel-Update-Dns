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
from pyopnsense import diagnostics

### Get IP via external service

def fetch_external_ip():
    url = 'https://api64.ipify.org'
    ip = urlopen(url).read().decode('utf-8')
    return ip

### Get IP via OPNsense API

def fetch_OPNsense(type = 'A', api_key = '', api_secret = '', opnsense_url = '', itf = ''):

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
    parser.add_argument('--ttl', default='300', help='Time To Live')
    parser.add_argument('--type', default='A', help='Type of record: A for IPV4 or AAAA for IPV6')
    parser.add_argument('--method', default='argument', help='The method to obtain the IP address', 
                        choices=['args', 'online', 'opnsense', 'interface'], required=True)
    parser.add_argument('--ip', help='The IPV4/IPV6 address when using the args method')
    parser.add_argument('--itf', help='The interface to poll when using the interface method')
    parser.add_argument('--name', help='Your record name, ie: ipv6.domain.com', required=True)
    parser.add_argument('--domain', help='The domain name containing the record name', required=True)
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
    if (args.method == 'arguments'):
        ip = args.ip
    elif(args.method == 'online'):
        print("Fetching current IP to use")
        ip = fetch_external_ip()
    elif(args.method == 'interface'):
        ip = '0.0.0.0'
    elif(args.method == 'opnsense'):
        ip = fetch_OPNsense(type, args.opn_key, args.opn_secret, args.opn_url, args.opn_itf)
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

    if ipFromDNS==ip:
        print("The same IP is already set! Exiting.")
        exit(0)

    # Update or add the record
    query = "&address=" + ip

    url = args.url + "/json-api/cpanel?cpanel_jsonapi_module=ZoneEdit&cpanel_jsonapi_func=" + ("add" if line == "0" else "edit") + "_zone_record&cpanel_jsonapi_apiversion=2&domain="+ domain + "&name=" + record + "&type=" + type + "&ttl=" + ttl + query
    if line != "0":
        url += "&Line=" + str(line)

    print("URL sent to the server: " + url)

    q = Request(url)
    q.add_header('Authorization', auth_string)
    a = urlopen(q).read().decode("utf-8")
    print("Response from the server: ")
    # TODO: Should parse the result
    print(a)