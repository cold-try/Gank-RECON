import dns.resolver
import re
import requests


def check_if_takeoverable(target):
    
    formated_target = target.split('//')[1]
    checklist = {
        '.agilecrm.com': ['No landing page found.', 'Sorry, this page is no longer available.'],
        '.airee.ru': ['Ошибка 402. Сервис Айри.рф не оплачен', 'на который вы заходите, не оплатил сервис Айри.рф. Доступ к сайту временно невозможен'],
        's3': ['NoSuchBucket', 'The specified bucket does not exist'],
        'awsdns': ['NoSuchBucket', 'The specified bucket does not exist'],
        '.elasticbeanstalk.com': ['404 Not Found'],
        'bitbucket': ['Repository not found'],
        '.createsend.com': ['Trying to access your account?'],
        '.updatemyprofile.com': ['Trying to access your account?'],
        '.forwardtomyfriend.com': ['Trying to access your account?'],
        'cargocollective.com': ['404 Not Found'],
        'digitalocean.com': ['Domain uses DO name servers with no records in DO'],
        'discourse.com': [''],
        'fly': ['404 Not Found'],
        'anima': ['Missing Website'],
        'fury': ['404: This page could not be found', 'Hello! Sorry, but the website'],
        'ghost.io': ['The thing you were looking for is no longer here, or never was'],
        'github': ["There isn't a GitHub Pages site here"],
        'hatenablog': ['404 Blog is not found'],
        'helpjuice.com': ["We could not find what you're looking for"],
        'helpscoutdocs.com': ['No settings were found for this company'],
        'herokuapp.com': ['No such app'],
        'herokudns.com': ['No such app'],
        'herokussl.com': ['No such app'],
        'intercom': ["Uh oh. That page doesn't exist"],
        'youtrack.cloud': ['is not a registered InCloud'],
        'kinsta': ['No Site For Domain'],
        'landingi.com': ['It looks like you’re lost...'],
        'launchrock.com': ['It looks like you may have taken a wrong turn somewhere'],
        'mashery': ['Unrecognized domain'],
        'cloudapp.net': [''],
        'cloudapp.azure.com': [''],
        'azurewebsites.net': [''],
        'blob.core.windows.net': [''],
        'azure-api.net': [''],
        'azurehdinsight.net': [''],
        'azureedge.net': [''],
        'azurecontainer.io': [''],
        'database.windows.net': [''],
        'azuredatalakestore.net': [''],
        'search.windows.net': [''],
        'azurecr.io': [''],
        'redis.cache.windows.net': [''],
        'azurehdinsight.net': [''],
        'servicebus.windows.net': [''],
        'visualstudio.com': [''],
        'netlify.com': ['Not Found - Request ID'],
        'ngrok.io': ['Tunnel '],
        'pantheon': ['404 error unknown site!'],
        'pingdom': ["Sorry, couldn't find the status page"],
        'readme.io': ['Project doesnt exist... yet!'],
        'myshopify.com': ['Sorry, this shop is currently unavailable'],
        'short': ['Link does not exist'],
        'smartjobboard': ['This job board website is either expired or its domain name is invalid'],
        'mysmartjobboard': ['This job board website is either expired or its domain name is invalid'],
        'smartling.com': ['Domain is not configured'],
        'strikinglydns': ['page not found'],
        'strikingly': ['page not found'],
        'surge': ['project not found'],
        'surveysparrow': ['Ouch! Account not found'],
        'tumblr': ["Whatever you were looking for doesn't currently exist at this address"],
        'tilda': ['Please renew your subscription'],
        'uberflip': ["Non-hub domain, The URL you've accessed does not provide a hub"],
        'uptimerobot': ['page not found'],
        'uservoice': ['This UserVoice subdomain is currently available!'],
        'webflow': ["The page you are looking for doesn't exist or has been moved"],
        'wixdns': ["Looks Like This Domain Isn't Connected To A Website Yet!"],
        'wix': ["Looks Like This Domain Isn't Connected To A Website Yet!"],
        'wordpress': ['Do you want to register'],
        'worksites': ['Hello! Sorry, but the website'],
        'squarespace': ['Domain Not Claimed']
    }

    try:
        for rdata in dns.resolver.resolve(formated_target, 'CNAME'):

            # Check CNAME record pointing
            for key in checklist:
                cname_regexp = re.compile(key)
                if cname_regexp.search(str(rdata.target)):

                    # Check the fingerprint
                    for fingerprint in checklist[key]:
                        fingerprint_regexp = re.compile(fingerprint)
                        r = requests.get(target)

                        if fingerprint_regexp.search(str(r.text)):
                            return True
    except:
        pass
    
    return False