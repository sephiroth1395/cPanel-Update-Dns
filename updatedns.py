import base64
import argparse
from urllib.parse import urlencode
from urllib.request import urlopen,Request
import xml.etree.ElementTree as etree

def fetch_external_ip(type):
    url = 'http://' + ("ipv6" if type == "AAAA" else "ipv4") + '.myexternalip.com/raw'
    ip = urlopen(url).read().decode('utf-8')[:-1]
    return ip

if __name__ == "__main__":
    try:
        from config import CONFIG
    except ImportError:
        print("Error: config.py NOT found")
        exit()

    # Show all arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--ttl', default='300', help='Time To Live')
    parser.add_argument('--type', default='AAAA', help='Type of record: A for IPV4 or AAAA for IPV6')
    parser.add_argument('--ip', help='The IPV4/IPV6 address (if known)')
    parser.add_argument('--value', help='The value of the TXT (if known)')
    parser.add_argument('--name', help='Your record name, ie: ipv6.domain.com', required=True)
    parser.add_argument('--domain', help='The domain name containing the record name', required=True)
    args = parser.parse_args()

    # Generate a auth_string to connect to cPanel
    auth_string = 'Basic ' + base64.b64encode((CONFIG['username']+':'+CONFIG['password']).encode()).decode("utf-8")

    domain = args.domain
    record = args.name
    if not record.endswith('.'):
        record += "."
    type = "A"
    if args.type.upper() == "AAAA" or args.type.upper() == "TXT":
        type = args.type.upper()
    ip = args.ip if args.ip != None else fetch_external_ip(type)
    ttl = args.ttl
    value = args.value if args.value != None else ""

    # Fetch existing DNS records
    q = Request(CONFIG['url'] + '/xml-api/cpanel?cpanel_xmlapi_module=ZoneEdit&cpanel_xmlapi_func=fetchzone&cpanel_xmlapi_apiversion=2&domain=' + domain)
    q.add_header('Authorization', auth_string)
    xml = urlopen(q).read().decode("utf-8")

    # Parse the records to find if the record already exists
    root = etree.fromstring(xml)
    line = "0"
    for child in root.find('data').findall('record'):
        if child.find('name') != None and child.find('name').text == record:
            line = str(child.find('line').text)
            break

    # Update or add the record
    query = "&address=" + ip
    if type == "TXT":
        query = "&" + urlencode( {'txtdata': value} )

    url = CONFIG['url'] + "/xml-api/cpanel?cpanel_xmlapi_module=ZoneEdit&cpanel_xmlapi_func=" + ("add" if line == "0" else "edit") + "_zone_record&cpanel_xmlapi_apiversion=2&domain="+ domain + "&name=" + record + "&type=" + type + "&ttl=" + ttl + query
    if line != "0":
        url += "&Line=" + line

    print(url)

    q = Request(url)
    q.add_header('Authorization', auth_string)
    a = urlopen(q).read().decode("utf-8")

    # TODO: Should parse the result
    print(a)
