import asyncio
from colorama import Fore, Style
from os.path import exists
from functions import *
from subdo_takeover import check_if_takeoverable
from subdo_bypass import check_if_bypassable
from subdo_bruteforce import bruteforce_launcher
from subdo_ports_scanner import port_scan
from subdo_google_dork import google_dork_sub
from subdo_webarchive import subdo_webarchive
from subdo_secret_finder import scan_for_secrets, get_js_files
from subdo_basicauth_bruteforce import b64_bruteforce_launcher


# ------------------------------------------------------------------------------------ # SETTINGS


logo()

first_time = False
bypass_infos = ""
target = input(f"{Fore.LIGHTYELLOW_EX}Enter the targeted domain : {Style.RESET_ALL}")

findings = []
results = {}
code_color = {'1':Fore.LIGHTWHITE_EX,'2':Fore.LIGHTGREEN_EX, '3':Fore.LIGHTMAGENTA_EX, '4':Fore.LIGHTRED_EX, '5':Fore.LIGHTCYAN_EX}

print('')
use_bruteforce = input(f"{Fore.LIGHTYELLOW_EX}Do you want to use the brute-force method? If yes enter <{Style.RESET_ALL} y {Fore.LIGHTYELLOW_EX}> :{Style.RESET_ALL} ").lower()
print('')
use_scanports = input(f"{Fore.LIGHTYELLOW_EX}Do you want to scan the ports? If yes enter <{Style.RESET_ALL} y {Fore.LIGHTYELLOW_EX}> :{Style.RESET_ALL} ").lower()

if use_scanports == 'y':
    scanports_option = input(f"{Fore.LIGHTYELLOW_EX}For the most popular ports enter <{Style.RESET_ALL} p {Fore.LIGHTYELLOW_EX}> , for a deeper scan enter {Style.RESET_ALL}any other letter{Fore.LIGHTYELLOW_EX} (can be longer or shorter depending on the number of subdomains found) : {Style.RESET_ALL}").lower()
    if scanports_option == 'p':
        top_ports = True
    else:
        top_ports = False
else: scanports_option=None

print('')
check_http_bypass = input(f"{Fore.LIGHTYELLOW_EX}Do you want to check if 403/401 responses are bypassable? If yes enter <{Style.RESET_ALL} y {Fore.LIGHTYELLOW_EX}> :{Style.RESET_ALL} ").lower()

print('')
use_bruteforce_basicauth = input(f"{Fore.LIGHTYELLOW_EX}Do you want subdomains returning a 401 code to be automatically bruteforced via the Authorization header (basic auth, base64)? If yes enter <{Style.RESET_ALL} y {Fore.LIGHTYELLOW_EX}> :{Style.RESET_ALL} ").lower()

print('')
use_scan_for_secrets = input(f"{Fore.LIGHTYELLOW_EX}Do you want to scan subdomains for secrets (api key, password..)? If yes enter <{Style.RESET_ALL} y {Fore.LIGHTYELLOW_EX}> :{Style.RESET_ALL} ").lower()
secrets_scan_depth = input(f"{Fore.LIGHTYELLOW_EX}Include the search for generic tokens in your secrets scan? This can make the scan longer and generate more false positives. If yes enter <{Style.RESET_ALL} y {Fore.LIGHTYELLOW_EX}> :{Style.RESET_ALL} ").lower()

print('')
print('----------------------------------------')


# ------------------------------------------------------------------------------------ # GOOGLE DORK


findings = google_dork_sub(target)


# ------------------------------------------------------------------------------------ # WEB ARCHIVE


findings = subdo_webarchive(target, findings)


# ------------------------------------------------------------------------------------ # EXTERNAL SERVICE


findings = external_service_call('crt_sh', target, findings) # ----------------------- # CRT.SH

findings = external_service_call('security_trails', target, findings) # -------------- # SECURITY TRAILS

findings = external_service_call('binary_edge', target, findings) # ------------------ # BINARYEDGE API

findings = external_service_call('censys', target, findings) # ----------------------- # CENSYS

findings = external_service_call('virus_total', target, findings) # ------------------ # VIRUSTOTAL API

findings = external_service_call('alienvault', target, findings) # ------------------- # ALIENVAULT API

findings = external_service_call('bevigil', target, findings) # ---------------------- # BEVIGIL API

findings = external_service_call('intelx', target, findings) # ----------------------- # INTELLIGENCE X API


# ------------------------------------------------------------------------------------ # SUBDO-BRUTEFORCE


if use_bruteforce == 'y':
    results = bruteforce_launcher(target, findings)


# ------------------------------------------------------------------------------------ # URLS TESTING 


total = len(findings) + len(results)

print(f"{Fore.LIGHTGREEN_EX}Total of subdomains found : {total}{Style.RESET_ALL}")
print('')
print(f'{Fore.LIGHTYELLOW_EX}Starting url testing...{Style.RESET_ALL}')

if use_scanports == 'y': print(f'[*] Port scan : {Fore.LIGHTGREEN_EX}ON{Style.RESET_ALL}')
else : print(f'[*] Port scan : {Fore.LIGHTRED_EX}OFF{Style.RESET_ALL}')

print(f'[*] 404/402 responses subdo-takeoverable check : {Fore.LIGHTGREEN_EX}ON{Style.RESET_ALL}')

if check_http_bypass=='y': print(f'[*] 403/401 responses bypass check : {Fore.LIGHTGREEN_EX}ON{Style.RESET_ALL}')
else: print(f'[*] 403/401 responses bypass check : {Fore.LIGHTRED_EX}OFF{Style.RESET_ALL}')

if use_bruteforce_basicauth=='y': print(f'[*] 401 responses Basic Auth bruteforce : {Fore.LIGHTGREEN_EX}ON{Style.RESET_ALL}')
else: print(f'[*] 401 responses Basic Auth bruteforce : {Fore.LIGHTRED_EX}OFF{Style.RESET_ALL}')

if use_scan_for_secrets=='y': print(f'[*] Secrets Finder : {Fore.LIGHTGREEN_EX}ON{Style.RESET_ALL}')
else: print(f'[*] Secrets Finder : {Fore.LIGHTRED_EX}OFF{Style.RESET_ALL}')


print('')

all_responses, all_html_pages = asyncio.run(url_testing(findings))
all_responses = dict_merge(all_responses, results)

for code in all_responses:
    color_of_code = code_color[str(code)[0]]
    print(f'--------------- Code {color_of_code}{code}{Style.RESET_ALL} ---------------')
    print('')

    for url in all_responses[code]:
        bypass_infos = ''

        # --------------------------------- # IS TAKEOVERABLE?
        if code==404 or code==402:
            is_takeoverable = check_if_takeoverable(str(url))
        else:
            is_takeoverable = False
        
        # --------------------------------- # IS BYPASSABLE? HTTP HEADER, HTTP VERB
        if code==403 or code==401:
            if check_http_bypass=='y':
                bypass_infos = check_if_bypassable(str(url))

            # ----------------------------- # BASIC AUTH BRUTEFORCE
            if code==401 and use_bruteforce_basicauth=='y':
                b64_bruteforce_launcher(str(url))

        # --------------------------------- # PORTS SCANNER
        if use_scanports == 'y':
            open_ports = port_scan(str(url).split('//')[1], top_ports=top_ports)
        else: open_ports = False

        if is_takeoverable:
            print(f"[{code}]{color_of_code} {url}{Style.RESET_ALL} --{Fore.LIGHTGREEN_EX} [!] Subdomain Potentially Takeoverable !{Style.RESET_ALL}")
        else:

            # --------------------------------- # CHECK IF THERE IS ANYTHING NEW SINCE THE LAST LAUNCH
            if open_ports:
                open_ports_format = str(open_ports)
                data_row = [code, url, open_ports_format]
            else: 
                data_row = [code, url]
            
            if exists(f'findings/{target}.csv'):
                any_news, types_of_news = csv_upload_check(target, data_row)
            else:
                write_on_csv(target, data_row, 'a+')
                first_time = True
                any_news = False

            if any_news:
                if not first_time:
                    news = f" -- {Fore.LIGHTGREEN_EX}[NEW]{Style.RESET_ALL} :"

                    for the_type, is_new in types_of_news.items():
                        if is_new: 
                            if news[-1]==':':
                                news += f" {the_type} "
                            else:
                                news += f", {the_type} "
            else:
                news = ""

            if use_scanports == 'y' and open_ports:
                print(f"[{code}]{color_of_code} {url}{Style.RESET_ALL} -- [{Fore.LIGHTYELLOW_EX}open ports{Style.RESET_ALL} : {open_ports_format.strip('[')}" + news + bypass_infos)
            else:
                print(f"[{code}]{color_of_code} {url}{Style.RESET_ALL} " + news + bypass_infos)

        # --------------------------------- # SECRETS FINDER
        if use_scan_for_secrets == 'y':
            files_to_scan = get_js_files(all_html_pages[url], target, url)
            files_to_scan.append([all_html_pages[url], target, url])
            for file in files_to_scan:
                scan_for_secrets(file[0], file[1], file[2], secrets_scan_depth)

    print('')

print('----------------------------------------')
print('')

print(f"{Fore.LIGHTYELLOW_EX}The results are saved in findings/{target}.csv{Style.RESET_ALL}")
if use_scan_for_secrets=='y': print(f"{Fore.LIGHTYELLOW_EX}The secrets are saved in findings/secrets/secrets_{target}.csv{Style.RESET_ALL}")
print('')
print('- End of program -')
print('')