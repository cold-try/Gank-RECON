import requests
import json
import asyncio
import httpx
import re
import csv
import os
from colorama import Fore, Style
from censys.search import CensysCertificates
from bs4 import BeautifulSoup


async def get_async(url):
    user_agent = get_info_config('userAgent')
    headers = {'User-Agent':user_agent}
    try:
        async with httpx.AsyncClient() as client:
            return await client.get(url, headers=headers, timeout=5)
    except:
        pass


async def url_testing(urls):
    responses = {}
    html_pages = {}
    resps = await asyncio.gather(*map(get_async, urls))
    data = [resp for resp in resps]

    for resp in data:
        if resp:
            if resp.status_code in responses:
                responses[resp.status_code].append(resp.url)
            else:
                responses[resp.status_code]=[resp.url]
            html_pages[resp.url]=resp.text

    return responses, html_pages


def external_service_call(targeted_service, target, findings):

    services = {
        'crt_sh': [crt_sh, 'CRT.SH', True],
        'security_trails': [securitytrails_api, 'Security trails API', False],
        'binary_edge': [binaryedge_api, 'BinaryEdge API', True],
        'censys': [censys_api, 'Censys API', True],
        'virus_total': [virustotal_api, 'VirusTotal API', True],
        'alienvault': [alienvault_api, 'AlienVault API', True],
        'bevigil': [bevigil_api, 'Bevigil API', True],
        'intelx': [intelx_api, 'Intelligence X API', True]
    }
    finding_counter = 0
    targeted_service_findings = services[targeted_service][0](target)

    print(f'{Fore.LIGHTYELLOW_EX}Starting - {services[targeted_service][1]} - ...{Style.RESET_ALL}')
    print('')
    print('----------------------------------------')
    print(f"{Fore.LIGHTGREEN_EX}")

    for subdo in targeted_service_findings:
        if services[targeted_service][2]:
            formatted_subdo = f"https://{subdo}"
        else:
            formatted_subdo = f"https://{subdo}.{target}"

        if formatted_subdo not in findings and '.' + target in formatted_subdo:
            findings.append(formatted_subdo)
            finding_counter += 1
            print(f"{Style.RESET_ALL}[+]{Fore.LIGHTGREEN_EX} {formatted_subdo}")

    if finding_counter == 0:
        print(f'{Style.RESET_ALL}{Fore.LIGHTRED_EX}[x] No unique results found.')

    print(f"{Style.RESET_ALL}")
    print('----------------------------------------')
    print('')
    print(f"Number of unique subdomains found :{Style.RESET_ALL}{Fore.LIGHTGREEN_EX} {finding_counter}{Style.RESET_ALL}")
    print('')

    return findings


def crt_sh(target):
    domains=[]
    url=f"https://crt.sh/?q={target}"

    try:
        req=requests.get(url)
        soup = BeautifulSoup(req.text, "html.parser")
        td=soup.find_all("td")

        for dom in td:
            domain = re.search(f"(.*)\.{target}", dom.getText())

            if domain:
                line_content = domain.group().split(f".{target}")
                
                for subdo in line_content:
                    re_format_subdo = f"{subdo}.{target}"
                    if subdo and re_format_subdo not in domains:
                        domains.append(re_format_subdo)
    except:
        pass
    
    return domains


def securitytrails_api(target):
    url = f"https://api.securitytrails.com/v1/domain/{target}/subdomains?children_only=false&include_inactive=true"
    headers = {
        "accept": "application/json",
        "APIKEY": get_info_config('apiKey', 'securitytrails')
    }
    response = requests.get(url, headers=headers)
    if response:
        response_to_json = json.loads(response.text)

        return response_to_json['subdomains']
    else:
        return []


def binaryedge_api(target):
    page = 1
    headers = {
        "X-Key": get_info_config('apiKey', 'binaryedge')
    }
    results = []
    
    while True:
        url = f"https://api.binaryedge.io/v2/query/domains/subdomain/{target}?page={page}"
        response = requests.get(url, headers=headers)
        response_to_json = json.loads(response.text)
        
        if 'events' in response_to_json:
            results += response_to_json['events']
            last_page = int(response_to_json['total']) / 100
            if last_page == page or last_page < page:
                break
            else:
                page += 1
        else:
            return []
    
    return results


def censys_api(target):
    CENSYS_API_ID = get_info_config('apiKey', 'CENSYS_API_ID')
    CENSYS_API_SECRET = get_info_config('apiKey', 'CENSYS_API_SECRET')
    subdomains = []

    try:
        censys_certificates = CensysCertificates(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)
        certificate_query = 'parsed.names: %s' % target

        certificates_search_results = censys_certificates.search(certificate_query, fields=['parsed.names'], max_records=1000)

        for search_result in certificates_search_results:
            subdomains.extend(search_result['parsed.names'])

        return list(subdomains)
    except:
        return []


def virustotal_api(target):
    virus_total = get_info_config('apiKey', 'virustotal')
    headers = {'x-apikey': virus_total}
    endpoint = f"https://www.virustotal.com/api/v3/domains/{target}/subdomains?limit=1000"
    results = []

    response = requests.get(endpoint, headers=headers)
    try: response_to_json = json.loads(response.text)
    except: response_to_json = {}

    if len(response_to_json) > 0:
        while True:
            try:
                for subdomain_data in response_to_json['data']:
                    results.append(subdomain_data['id'])

                if len(response_to_json['links'])>1:
                    response = requests.get(response_to_json['links']['next'], headers=headers)
                    response_to_json = json.loads(response.text)
                else:
                    break
            except: pass

    return results


def alienvault_api(target):
    endpoint = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns"
    response = requests.get(endpoint)
    response_to_json = json.loads(response.text)
    results = []

    if 'passive_dns' in response_to_json:
        for subdomain in response_to_json['passive_dns']:
            if target in subdomain['hostname']:
                results.append(subdomain['hostname'])
    
    return results


def bevigil_api(target):
    bevigil_key = get_info_config('apiKey', 'bevigil')
    endpoint = f"http://osint.bevigil.com/api/{target}/subdomains/"
    headers = {'X-Access-Token': bevigil_key}
    response = requests.get(endpoint, headers=headers)
    response_to_json = json.loads(response.text)
    results = []

    if 'subdomains' in response_to_json:
        for subdomain in response_to_json['subdomains']:
            results.append(subdomain)
    
    return results


def intelx_api(target):
    intelx_key = get_info_config('apiKey', 'intelligencex')
    endpoint = "https://2.intelx.io/phonebook/search"
    headers = {"x-key": intelx_key}
    payload = {
        "term":target,
        "maxresults":10000,
        "media":0,
        "target":1,
        "timeout":20
    }
    results = []

    try:
        response = requests.post(endpoint, headers=headers,  data=json.dumps(payload))
        response_to_json = json.loads(response.text)

        result_id = response_to_json['id']
        result_endpoint = f"https://2.intelx.io/phonebook/search/result?id={result_id}&limit=10000"
        response = requests.get(result_endpoint, headers=headers)
        response_to_json = json.loads(response.text)

        for subdomain in response_to_json['selectors']:
            results.append(subdomain['selectorvalue'])
    except: pass
    
    return results


def subdo_filter(url, target_size):
    splitter = url.split('//')
    return splitter[1][:-target_size-1]


def write_on_csv(name, data, action):
    with open(f'findings/{name}.csv', action, newline='') as file:
        writer = csv.writer(file)
        if action == 'a+':
            writer.writerow(data)
        else:
            writer.writerows(data)


def csv_upload_check(name, data):

    with open(f'findings/{name}.csv', 'r') as file:
        reader = csv.reader(file)
        any_news = False
        types_of_news = {'HTTP Code':False, 'Subdomain':True, 'Port':False}
        lines = []

        for row in reader:
            if row[1].split('//')[1] == str(data[1]).split('//')[1]:
                types_of_news['Subdomain']=False

                if row[0]!=str(data[0]):
                    types_of_news['HTTP Code']=True
                    any_news = True

                if len(data)>2:
                    if len(row)>2:
                        if row[2]!=data[2]:
                            types_of_news['Port']=True
                            any_news = True
                    else:
                        types_of_news['Port']=True
                        any_news = True

                if any_news:
                    lines.append(data)
                else:
                    lines.append(row)            
            else:
                lines.append(row)

        if any_news:
            write_on_csv(name, lines, 'w')
        elif types_of_news['Subdomain']:
            write_on_csv(name, data, 'a+')
            any_news=True

    return any_news, types_of_news


def get_info_config(root, spec=None):
    file = open('config.json')
    data = json.load(file)

    if spec:
        return data[root][spec]
    else:
        return data[root]


def load_wordlist(filename):
    try:
        wordlist = open(f'bruteforce_lists/{filename}','r').read().split("\n")
    except:
        root = os.path.abspath(os.path.dirname(__file__))
        filename = os.path.join(root, "", filename)
        wordlist = open(f'bruteforce_lists/{filename}','r').read().split("\n")
    return filter(None, wordlist)


def dict_merge(dict1, dict2):
    for code in dict2:
        if code in dict1:
            dict1[code].append(dict2[code])
        else:
            dict1[code]=[dict2[code]]
    return dict1


def logo():
    print(rf"""{Fore.LIGHTWHITE_EX}
      (
       \                      
        )     __
##-------->  / _`  /\  |\ | |__/
        )    \__> /~~\ | \| |  \  recon.
       /
      (
    {Style.RESET_ALL}""")
    print('By zhero_ / Twitter @uthor : @blank_cold')
    print('')
    print('------------------------------------------')
    print('')
