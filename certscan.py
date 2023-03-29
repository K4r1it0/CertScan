import json
import urllib.request
import ipaddress
import subprocess
import sys
import os 

##{region}.json massdns json restuls
##{region}_masscan_parsed.txt massscan parsed ip:port
##{region}_ips.txt masscan ips input
##{region}_results.txt final results

done_regions = []

def exists(file):
    if os.path.isfile(file):
        return True
    else:
        return False


def get_ip_range(vendor):
    ips_by_region = {}
    if vendor == "AWS" :
        print("Looping through AWS's IP prefixes and converting CIDRs to IP List")
        url = 'https://ip-ranges.amazonaws.com/ip-ranges.json'
        response = urllib.request.urlopen(url)
        data = response.read().decode('utf-8')
        json_data = json.loads(data)
        for prefix in json_data['prefixes']:
            if prefix['service'] == 'EC2':
                region = f"AWS_{prefix['region']}"
                ip_prefix = prefix['ip_prefix']
                ips = [str(ip) for ip in ipaddress.IPv4Network(ip_prefix)]
                if region not in ips_by_region:
                    ips_by_region[region] = []
                ips_by_region[region] += ips

    if vendor == "GCP":
        print("Looping through GCP's IP prefixes and Converting CIDRs to IP List")
        url = 'https://www.gstatic.com/ipranges/cloud.json'
        response = urllib.request.urlopen(url)
        data = response.read().decode('utf-8')
        json_data = json.loads(data)
        for prefix in json_data['prefixes']:
            if "ipv4Prefix" in prefix:
                region = f"GCP_{prefix['scope']}"
                ip_prefix = prefix['ipv4Prefix']
                ips = [str(ip) for ip in ipaddress.ip_network(ip_prefix)]
                if region not in ips_by_region:
                    ips_by_region[region] = []
                ips_by_region[region] += ips
    return ips_by_region


def parse_tls_results(tls_results):
    parsed_results = []
    for result in tls_results['data']:
        host = f"{result['ip']}:{result['port']}"
        try:
            for cert in result.get('certificateChain',[]):
                subject_alt_names = cert.get("subjectAltName", "")
                subject_cn = cert.get("subjectCN", "")
                issuer = cert.get("issuer", "")
                subject = cert.get("subject", "")
                parsed_results.append({
                    "host": host.replace('"', '').replace("'", ""),
                    "subjectAltName": subject_alt_names.replace('"', '').replace("'", ""),
                    "subjectCN": subject_cn.replace('"', '').replace("'", ""),
                    "issuer": issuer.replace('"', '').replace("'", ""),
                    "subject": subject.replace('"', '').replace("'", "")
                })
        except Exception as a:
            print(a,"parse_tls_results Function Error",host)
    return parsed_results

def output(file,content,ext="txt"):
        with open(f"{file}.{ext}", 'w') as f:
                f.write(content)

def run_tls_scan(region):
    tls_scan_cmd = f"cat {region}_masscan_parsed.txt | /root/tools/tls-scan/tls-scan --json --concurrency=3000 --cacert=/root/tools/tls-scan/ca-bundle.crt"
    print(f"Running tls-scan for {region}")
    process = subprocess.Popen(tls_scan_cmd, shell=True, stdout = subprocess.PIPE,stderr = subprocess.DEVNULL)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        print(f"tls-scan failed with error:\n{stderr}")
        return []
    newline_sep_json_str = str(stdout.decode("utf-8"))
    json_str_list = newline_sep_json_str.strip().split('\n')
    json_dict_list = []
    for json_str in json_str_list:
        if "false, }" in json_str:
            json_str = json_str.replace("false, }","false}")
        if len(json_str) > 0:
            try:
                json_dict = json.loads(json_str)
                json_dict_list.append(json_dict)
            except Exception as a:
                print(a,json_str,"run_tls_scan Function Error")
                continue
    merged_dict = {"data": json_dict_list}
    return merged_dict

def main():
    ips_by_region = {**get_ip_range("AWS"),**get_ip_range("GCP")}
    for region, ips in ips_by_region.items():
        if region not in done_regions:
            ip_list_str = "\n".join(ips)
            output(f"{region}_ips",ip_list_str)
            rate = 1500000
            masscan_cmd = f"/usr/bin/masscan -iL {region}_ips.txt -sS --wait 20 --ports '81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9092,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672,80,443' -oJ {region}.json --rate {rate}"
            print(f"Running Masscan for {region} on {len(ips)} IP Addresses with {rate} Rate")
            process = subprocess.Popen(masscan_cmd, shell=True)#stderr=subprocess.DEVNULL
            process.communicate()
            if os.path.getsize(f'{region}.json') != 0:
                with open(f'{region}.json') as f:
                    try:
                        regions_data = json.load(f)
                        all_ips = ''
                        for obj in regions_data:
                            ip = obj['ip']
                            for port_obj in obj['ports']:
                                port = port_obj['port']
                                all_ips += f"{ip}:{port}\n"
                        output(f"{region}_masscan_parsed",all_ips)
                        tls_results = run_tls_scan(region)
                        parsed_results = parse_tls_results(tls_results)
                        output(f"{region}_results",str(parsed_results),"json")
                    except Exception as a:
                        print(a,"Main Function Error",f'{region}.json')
            else:
                continue
        else:
            print(f"{region} is skipped")
            continue

if __name__ == "__main__":    
    main()


