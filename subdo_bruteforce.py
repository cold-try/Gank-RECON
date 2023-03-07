import requests
import concurrent.futures
from colorama import Fore, Style
from functions import get_info_config, load_wordlist


user_agent = get_info_config('userAgent')
headers = {"user-agent": user_agent}



def test_https(url):
    try:
        resp = requests.get("https://"+url, headers=headers, timeout=get_info_config('timeout'))
        return [resp.status_code, resp.headers["Server"] if "Server" in resp.headers.keys() else ""]
    except:
        return []


def test_http(url):
    try:
        resp = requests.get("http://"+url, headers=headers, timeout=get_info_config('timeout'))
        return [resp.status_code, resp.headers["Server"] if "Server" in resp.headers.keys() else ""]
    except:
        return []


def scan(domain, subdomain, results):
    req = []
    target = subdomain + "." + domain
    https = test_https(target)
    prefix = ''
    
    if https:
        for item in https:
            req.append(item)
        prefix = 'https://'
    else:
        http = test_http(target)
        if http:
            for item in http:
                req.append(item)
            prefix = 'http://'
                
    if len(req) > 0:
        print(f"[+]{Fore.LIGHTGREEN_EX} {prefix}{target}{Style.RESET_ALL}")
        return results.update({req[0]: prefix+target})


def bruteforce_launcher(domain, findings):

    print(f'{Fore.LIGHTYELLOW_EX}Starting - Subdomains BruteForce ... (This may be longer or shorter depending on the length of the wordlist){Style.RESET_ALL}')
    print('')
    print('----------------------------------------')
    print('')

    results = {}
    wordlist = list(load_wordlist(get_info_config('wordList')))
    wordlist = sorted(wordlist, key=str.lower)
    wordlist_length = len(wordlist)

    print(f'[*] Wordlist length : {wordlist_length}')
    print('')

    with concurrent.futures.ThreadPoolExecutor(max_workers=get_info_config('threads')) as executor:
        results_executor = {executor.submit(scan, domain, subdomain, results) for subdomain in wordlist}

        for item in concurrent.futures.as_completed(results_executor):
            if item.result() != None:
                print(item.result())

    for subdo in results.copy():
        if results[subdo] in findings:
            del results[subdo]

    if len(results) == 0:
                print(f'{Style.RESET_ALL}{Fore.LIGHTRED_EX}[x] No unique results found.')

    print(f"{Style.RESET_ALL}")
    print('----------------------------------------')
    print('')
    print(f"Number of unique subdomains found :{Style.RESET_ALL}{Fore.LIGHTGREEN_EX} {len(results)}{Style.RESET_ALL}")
    print('')

    return results