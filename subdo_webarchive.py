import requests
import re
from colorama import Fore, Style



def wayback_machine(target):
    
    url=f"https://web.archive.org/cdx/search/cdx?url=*.{target}&output=text&fl=original&collapse=urlkey"
    regex_pattern=f"https?://[www\.]?[0-9a-zA-Z_-]*.{target}"
    try:
        req=requests.get(url, timeout=10)
        findings=re.findall(regex_pattern, req.text)
        uniques_findings = list(dict.fromkeys(findings))
    except:
        uniques_findings = list()
    return uniques_findings


def subdo_webarchive(target, findings):

    print(f'{Fore.LIGHTYELLOW_EX}Starting - Web Archive - ...{Style.RESET_ALL}')
    print('')
    print('----------------------------------------')
    print(f"{Fore.LIGHTGREEN_EX}")

    webarchive_counter = 0
    webarchive_findings = wayback_machine(target)

    for subdo in webarchive_findings:
        if subdo not in findings:
            webarchive_counter += 1
            findings.append(subdo)
            print(f"{Style.RESET_ALL}[+]{Fore.LIGHTGREEN_EX} {subdo}")

    if webarchive_counter == 0:
        print(f'{Style.RESET_ALL}{Fore.LIGHTRED_EX}[x] No unique results found.')

    print(f"{Style.RESET_ALL}")
    print('----------------------------------------')
    print('')
    print(f"Number of unique subdomains found :{Style.RESET_ALL}{Fore.LIGHTGREEN_EX} {webarchive_counter}{Style.RESET_ALL}")
    print('')

    return findings