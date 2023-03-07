import requests
import json
import re
import csv
import http
from os.path import exists
from colorama import Fore, Style
from functions import get_info_config


http.client._MAXHEADERS = 1000
FALSE_POSITIVE = [
    'false', 'true', 'incorrect', 'details', 'settings', 'attribute', 'return', 'deductions', 'information', 'success', 'void', 'type', 
    'access_token', 'same-origin', "explore", "enable", "missing", "provide", 'api":"http', 'api:"http', "include", "consul", "= config", 
    "config", "advertising",'""', "getparam", "guest", "giventoken", "this.", "label", "function", 'null', 'await', 'refresh', 'index', 
    'invalid', 'boolean', 'login', 'phone', 'get', 'init', 'sign', 'reset', 'with', 'undef', 'string', 'verify', 'fetch', 'data', 'option',
    'host', 'new', 'forgot', 'show', 'redirect', 'set', 'call', 'json', 'current', 'allow', 'default', 'n.', 'e.', 'i.', 'r.', 'u.', 't.', 
    '"password', ' password', 'anonymous', 'error', 'repository', '.concat', 'object'
]
DONT_NOTIFY = ['Generic', 'Authorization basic', 'AWS S3 API', 'AWS URL']


def scan_for_secrets(html, target, url, secrets_scan_depth):
    file = open('regex_patterns.json')
    secrets_fingerprints = json.load(file)
    url_root_regex = r'(?:[^@\/\n]+@)?(?:\.)?([^:\/\n]+)'
    findings = []

    for key in secrets_fingerprints:
    
        if secrets_scan_depth != 'y':
            if key not in DONT_NOTIFY:
                finding=re.findall(secrets_fingerprints[key], html)
            else:
                finding=None
        else:
            finding=re.findall(secrets_fingerprints[key], html)


        if finding:
            for info in finding:
                valid=True
                
                if secrets_scan_depth=='y':
                    for word in FALSE_POSITIVE:
                        if word in info.lower():
                            valid=False

                if valid:
                    leak = info.strip()
                    valid_finding = [key, leak, url]

                    if valid_finding not in findings:
                        url_root = re.findall(url_root_regex, str(url))

                        is_new = is_new_secret(target, leak)
                        if is_new:
                            notif_text_output = f"{Fore.LIGHTGREEN_EX}[NEW]{Style.RESET_ALL}"
                        else:
                            notif_text_output = ""

                        print(f"[{Fore.LIGHTBLUE_EX}SECRET{Style.RESET_ALL}][{Fore.LIGHTWHITE_EX}{key}{Style.RESET_ALL}] {Fore.LIGHTBLUE_EX}[{Style.RESET_ALL}{Fore.LIGHTWHITE_EX}{leak}{Style.RESET_ALL}{Fore.LIGHTBLUE_EX}]{Style.RESET_ALL} {Fore.LIGHTBLUE_EX}({Style.RESET_ALL}source: {Fore.BLUE}{url_root[1]}{Style.RESET_ALL} - {Fore.YELLOW}saved{Style.RESET_ALL}{Fore.LIGHTBLUE_EX}){Style.RESET_ALL} {notif_text_output}")
                        findings.append({"finding":valid_finding, "is_new":is_new})
    
    if len(findings)>0:
        with open(f'findings/secrets/secrets_{target}.csv', 'a') as file:
            writer = csv.writer(file)

            for secret in findings:
                if secret['is_new']:
                    writer.writerow(secret['finding'])



def get_js_files(html, target, scanned_url):
    user_agent = get_info_config('userAgent')
    headers = {'User-Agent':user_agent}
    js_path_regex = r"((\/|\/\/|https?:\/\/)[a-z0-9_@\-^!#$%&+={}.\/\\\[\]]+\.js)"
    findings = re.findall(js_path_regex, html)
    js_urls = []
    js_files = []

    for path in findings:
        url=path[0]
        if url not in js_urls:
            if url[0]=='/':
                url=str(scanned_url)+url
            js_urls.append(url)
            try:
                req=requests.get(url, headers=headers)
                js_files.append([req.text, target, url])
            except:
                pass

    return js_files


def is_new_secret(target, secret):
    if exists(f'findings/secrets/secrets_{target}.csv'):
        with open(f'findings/secrets/secrets_{target}.csv', 'r') as file:
            reader = csv.reader(file)

            for row in reader:
                # To save a secret already found on another source, remove access via the index
                if row[1] == secret:
                    return False
        return True
    else:
        return True