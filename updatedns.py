#!/usr/bin/env python3

##### Python cPanel DNS update
### Based on script from nikigre/cPanel-Update-Dns
### Updated by Eric Viseur <eric.viseur@gmail.com> to support fetching the 
### IP addresses from OPNsense API

### Imports

import base64
import argparse
import urllib3
from urllib.request import urlopen,Request
import json

### Get IP via external service
def fetch_external_ip(type):

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
def fetch_interface_ip(itf, type):

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
def fetch_OPNsense(api_key = '', api_secret = '', opnsense_url = '', itf = '', type = ''):

    try:
        urllib3.disable_warnings()
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

### Run the IP date sequence
def do_IP_update(args):

    # Generate a auth_string to connect to cPanel
    auth_string = 'Basic ' + base64.b64encode((args.username+':'+args.password).encode()).decode("utf-8")

    domain = args.domain
    record = args.name
    if not record.endswith('.'):
        record += "."
    
    type = args.type.upper()

    # Obtain the IP address
    if(args.verbose): print("INFO - Obtaining IP address for record " + type + " using method " + args.method)

    if (args.method == 'arguments'):
        ip = args.ip
    elif(args.method == 'online'):
        ip = fetch_external_ip(type)
    elif(args.method == 'interface'):
        ip = fetch_interface_ip(args.itf, type)
    elif(args.method == 'opnsense'):
        ip = fetch_OPNsense(args.opn_key, args.opn_secret, args.opn_url, args.opn_itf, type)
    else:
        print('ERROR - Unexpected IP extraction method.')
        return(1)

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
        return(0)

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
        return(1)

    return(0)

### Main routine

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    try:
        from config import CONFIG
    except ImportError:
        pass

    parser.add_argument('-t', '--type', default='A', help='Type of record: A for IPV4 or AAAA for IPV6 (default: %(default)s)')
    parser.add_argument('--username', help='cPanel username')
    parser.add_argument('--password', help='cPanel password')
    parser.add_argument('--url', help='URL to your cPanel')
    parser.add_argument('--opn_itf', help='OPNsense method only: the WAN interface (i.e. vtnet0)')
    parser.add_argument('--opn_url', help='OPNsense method only: the API url (i.e. http://192.168.0.1/api')
    parser.add_argument('--opn_key', help='OPNsense method only: the API key')
    parser.add_argument('--opn_secret', help='OPNsense method only: the API secret')
    parser.add_argument('--ttl', default='14400', help='Time To Live (default: %(default)s)')
    parser.add_argument('-m', '--method', default='argument', help='The method to obtain the IP address', 
                         choices=['args', 'online', 'opnsense', 'interface'])
    parser.add_argument('--ip', help='The IPV4/IPV6 address when using the args method')
    parser.add_argument('--itf', help='The interface to poll when using the interface method')
    parser.add_argument('-n', '--name', help='Your record name, ie: ipv6.domain.com')
    parser.add_argument('-d', '--domain', help='The domain name containing the record name')
    parser.add_argument('-s', '--server', help='Run an HTTP daemon to handle update requests on demand', action='store_true')
    parser.add_argument('-p', '--port', default='8080', help='Port for the HTTP daemon (default: %(default)s)')
    parser.add_argument('-v', '--verbose', help='Display extra information.  If not set only errors are printed', action='store_true')
    
    args = parser.parse_args()

    if "CONFIG" in locals():
        
        if 'username' in CONFIG: args.username = CONFIG['username']
        if 'password' in CONFIG: args.password = CONFIG['password']
        if 'url' in CONFIG: args.url = CONFIG['url']
        if 'ttl' in CONFIG: args.ttl = CONFIG['ttl']
        if 'type' in CONFIG: args.type = CONFIG['type']

        if 'name' in CONFIG:
            args.name = CONFIG['name']                        
        elif (args.name is None):
            print("ERROR - Missing record name")
            exit(1)

        if 'domain' in CONFIG:
            args.domain = CONFIG['domain']
        elif (args.domain is None):
            print("ERROR - Missing cPanel zone name")
            exit(1)

        if (args.server == True):
            if 'port' in CONFIG:
                args.port = CONFIG['port']

        if 'method' in CONFIG:
            args.method = CONFIG['method']
        elif (args.method is None):
            print("ERROR - Missing update method")
            exit(1)

        if (args.method == 'interface'):
            if 'itf' in CONFIG:
                args.itf = CONFIG['itf']
            elif (args.itf is None):
                print("ERROR - Missing network interface")
                exit(1)

        if (args.method == 'args'):
            if 'ip' in CONFIG:
                args.ip = CONFIG['ip']
            elif (args.ip is None):
                print("ERROR - Missing IP address")
                exit(1)

        if (args.method == 'opnsense'):
            if 'opn_itf' in CONFIG:
                args.opn_itf = CONFIG['opn_itf']
            elif (args.opn_itf is None):
                print("ERROR - Missing OPNsense interface")
                exit(1)
            if 'opn_url' in CONFIG:
                args.opn_url = CONFIG['opn_url']
            elif (args.opn_url is None):
                print("ERROR - Missing OPNsense API URL")
                exit(1)
            if 'opn_key' in CONFIG:
                args.opn_key = CONFIG['opn_key']
            elif (args.opn_key is None):
                print("ERROR - Missing OPNsense API key")
                exit(1)
            if 'opn_secret' in CONFIG:
                args.opn_secret = CONFIG['opn_secret']
            elif (args.opn_secret is None):
                print("ERROR - Missing OPNsense API secret")
                exit(1)

    ##### 

    if(args.method == 'interface'): import netifaces
    elif(args.method == 'opnsense'): from pyopnsense import diagnostics

    ##### 

    if(args.server == True):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        class MyServer(BaseHTTPRequestHandler):
            def do_GET(self):

                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()

                # Update the DNS record  
                if(self.path == '/update'):
                    # Do the update
                    args.type = 'A'
                    result_v4 = do_IP_update(args)
                    args.type = 'AAAA'
                    result_v6 = do_IP_update(args)

                    # Define return 
                    if (result_v4 == 0) and (result_v6 == 0): success = True
                    else: success = False

                    # Return webserver answer 
                    if(success == True):
                        self.wfile.write(bytes("OK", "utf-8"))
                    else:
                        self.wfile.write(bytes("FAIL", "utf-8"))
                else:
                    self.wfile.write(bytes("<html><head><title>cPanel-Update-Dns</title></head>", "utf-8"))
                    self.wfile.write(bytes("<p>Request: %s</p>" % self.path, "utf-8"))
                    self.wfile.write(bytes("<body>", "utf-8"))
                    self.wfile.write(bytes("<p>This is not a valid HTTP request.</p>", "utf-8"))
                    self.wfile.write(bytes("</body></html>", "utf-8"))

        webServer = HTTPServer(("", int(args.port)), MyServer)
        if(args.verbose): print("INFO - Server started http://0.0.0.0:%s" % (args.port))

        try:
            webServer.serve_forever()
        except KeyboardInterrupt:
            pass

        webServer.server_close()
        if(args.verbose): print("INFO - Server stopped.")

    ##### 

    else:
        returnval = do_IP_update(args)
        exit(returnval)