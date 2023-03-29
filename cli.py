import json
import requests
import sys

data = requests.get(f"http://139.144.225.136:5000/ssl?search_string={sys.argv[1]}").json()

domains = set()  # Create a set to store the extracted domains

for item in data:
    issuer_domain = ''
    subject_domain = ''
    subject_alt_domains = []
    try:
        issuer_domain = item.get('issuer', '').split('CN=')[1]
    except (IndexError, KeyError) as e:
        print(f"Error while extracting issuer domain: {e}")
    try:
        subject_domain = item.get('subject', '').split('CN=')[1]
    except (IndexError, KeyError) as e:
        print(f"Error while extracting subject domain: {e}")
    try:
        subject_alt_names = item.get('subjectAltName', '').split(',')
        for name in subject_alt_names:
            if 'DNS:' in name:
                subject_alt_domains.append(name.split('DNS:')[1])
    except (IndexError, KeyError) as e:
        print(f"Error while extracting subject alternative names: {e}")
    domains.update([issuer_domain, subject_domain] + subject_alt_domains)

# Print the unique domains
for domain in domains:
    print(domain)
