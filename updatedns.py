import base64
import argparse
from urllib.request import urlopen,Request
import json

def fetch_external_ip():
    url = 'https://api64.ipify.org'
    ip = urlopen(url).read().decode('utf-8')[:-1]
    return ip

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    try:
        from config import CONFIG
    except ImportError:
        parser.add_argument('--username', help='cPanel username', required=True)
        parser.add_argument('--password', help='cPanel password', required=True)
        parser.add_argument('--url', help='URL to your cPanel', required=True)

    # Show all arguments
    parser.add_argument('--ttl', default='300', help='Time To Live')
    parser.add_argument('--type', default='A', help='Type of record: A for IPV4 or AAAA for IPV6')
    parser.add_argument('--ip', help='The IPV4/IPV6 address')
    parser.add_argument('--name', help='Your record name, ie: ipv6.domain.com', required=True)
    parser.add_argument('--domain', help='The domain name containing the record name', required=True)
    args = parser.parse_args()

    if "CONFIG" in locals():
        args.username = CONFIG['username']
        args.password = CONFIG['password']
        args.url = CONFIG['url']

    # Generate a auth_string to connect to cPanel
    auth_string = 'Basic ' + base64.b64encode((args.username+':'+args.password).encode()).decode("utf-8")

    domain = args.domain
    record = args.name
    if not record.endswith('.'):
        record += "."
    
    type = args.type.upper()

    if args.ip != None:
        ip = args.ip
    else:
        print("Fetching current IP to use")
        ip = fetch_external_ip()

    ttl = args.ttl

    # Fetch existing DNS records
    q = Request(args.url + '/json-api/cpanel?cpanel_jsonapi_module=ZoneEdit&cpanel_jsonapi_func=fetchzone&cpanel_jsonapi_apiversion=2&domain=' + domain)
    q.add_header('Authorization', auth_string)
    xml = urlopen(q).read().decode("utf-8")

    # Parse the records to find if the record already exists
    root = json.loads(xml)

    line = "0"
    for i in range(0, len(root["cpanelresult"]["data"][0]["record"])):
        if "name" in root["cpanelresult"]["data"][0]["record"][i]:
            if root["cpanelresult"]["data"][0]["record"][i]["name"] == record:
                line = root["cpanelresult"]["data"][0]["record"][i]["line"]
                break

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