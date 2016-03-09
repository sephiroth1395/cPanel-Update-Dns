import base64
from urllib.request import urlopen,Request
import xml.etree.ElementTree as etree

if __name__ == "__main__":
    try:
        from config import CONFIG
    except ImportError:
        print("Error: config.py NOT found")
        exit()

    # Generate a auth_string to connect to cPanel
    auth_string = 'Basic ' + base64.b64encode((CONFIG['username']+':'+CONFIG['password']).encode()).decode("utf-8")

    domain = "birkoss.com"
    record = "ipv6.birkoss.com."
    ip = "11:222:33:44:55:66:77:88"
    type = "AAAA"
    ttl = "300"

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
    url = CONFIG['url'] + "/xml-api/cpanel?cpanel_xmlapi_module=ZoneEdit&cpanel_xmlapi_func=" + ("add" if line == "0" else "edit") + "_zone_record&cpanel_xmlapi_apiversion=2&domain="+ domain + "&name=" + record + "&type=" + type + "&address=" + ip + "&ttl=" + ttl
    if line != "0":
        url += "&Line=" + line

    q = Request(url)
    q.add_header('Authorization', auth_string)
    a = urlopen(q).read().decode("utf-8")

    # TODO: Should parse the result
    print(a)
