import json
import requests
import sys


if len(sys.argv) < 2:
    print("Error: Please provide a keyword : python cli.py 'keyword' ")
    sys.exit()

data = requests.get(f"http://139.144.225.136:5050/ssl?search_string={sys.argv[1]}").json()

domains = set()  # Create a set to store the extracted domains

for item in data:
    issuer_domain = ''
    subject_domain = ''
    subject_alt_domains = []
    host = item.get('host', '')
    try:
        issuer_domain = item.get('issuer', '').split('CN=')[1].split(';')[0].strip().replace("*.","")
    except (IndexError, KeyError):
        pass
    try:
        subject_domain = item.get('subject', '').split('CN=')[1].split(';')[0].strip().replace("*.","")
    except (IndexError, KeyError):
        pass
    try:
        subject_alt_names = item.get('subjectAltName', '').split(',')
        for name in subject_alt_names:
            if 'DNS:' in name:
                subject_alt_domains.append(name.split('DNS:')[1].strip().replace("*.",""))
    except (IndexError, KeyError):
        pass
    domains.update([domain for domain in [issuer_domain, subject_domain, host] + subject_alt_domains if domain])

# Print the unique domains
for domain in domains:
    print(domain)
