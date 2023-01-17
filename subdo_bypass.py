import requests
from colorama import Fore, Style
from functions import get_info_config



def check_if_bypassable(targeted_url):
    user_agent = get_info_config('userAgent')
    BAD_CODES = [403, 404, 401, 405, 400, 501, 500, 502, 503, 505, 511]
    HTTP_VERBS = ['POST', 'PUT', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH', 'HEAD', 'INVENTED']
    HTTP_HEADERS = {
        'X-Originating-IP': '127.0.0.1',
        'X-Custom-IP-Authorization': '127.0.0.1',
        'X-Forwarded-For': ['127.0.0.1', '127.0.0.1:80', 'http://127.0.0.1'],
        'X-Forwarded': '127.0.0.1',
        'Forwarded-For': '127.0.0.1',
        'X-Remote-IP': '127.0.0.1',
        'X-Remote-Addr': '127.0.0.1',
        'X-ProxyUser-Ip': '127.0.0.1',
        'X-Original-URL': '127.0.0.1',
        'Client-IP': '127.0.0.1',
        'X-Client-IP': '127.0.0.1',
        'True-Client-IP': '127.0.0.1',
        'Cluster-Client-IP': '127.0.0.1',
        'X-ProxyUser-Ip': '127.0.0.1',
        'X-Host': '127.0.0.1',
        'X-Forwarded-Host': '127.0.0.1',
        'Host': 'localhost',
    }
    HTTP_HEADERS['User-Agent']=user_agent
    HTTP_HEADERS['Content-Length']=1

    s = requests.Session()
    for verb in HTTP_VERBS:
        try:
            req = requests.Request(verb, targeted_url, headers=HTTP_HEADERS)
            prepped = req.prepare()
            resp = s.send(prepped)

            code_resp = resp.status_code
            if code_resp not in BAD_CODES:
                return f" --{Fore.LIGHTGREEN_EX} [!] HTTP verb tampering : {verb} request enabled !{Style.RESET_ALL}" 
        except:
            pass
    
    for name, value in HTTP_HEADERS.items():
        try:
            if type(value)==list:
                for current_value in value:
                    headers = {name: current_value}
                    headers['User-Agent']=user_agent
                    headers['Content-Length']=1
                    req = requests.get(targeted_url, headers=headers)

                    if req.status_code not in BAD_CODES:
                        return f" --{Fore.LIGHTGREEN_EX} [!] Potentially bypassable with HTTP header '{name}:{current_value}'{Style.RESET_ALL}"
            else:
                headers = {name: value}
                headers['User-Agent']=user_agent
                headers['Content-Length']=1
                req = requests.get(targeted_url, headers=headers)

                if req.status_code not in BAD_CODES:
                    return f" --{Fore.LIGHTGREEN_EX} [!] Potentially bypassable with HTTP header '{name}:{value}'{Style.RESET_ALL}"
        except:
            pass
    
    return ""