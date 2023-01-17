from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from colorama import Fore, Style
from time import sleep
from random import shuffle
from functions import get_info_config, subdo_filter



def google_dork_sub(target):

    options = webdriver.ChromeOptions() 
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option('useAutomationExtension', False)
    options.add_argument("--disable-blink-features")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument("--start-maximized")
    options.add_argument('--window-size=1920,1080')
    options.add_argument("--headless")

    print('')
    print(f'{Fore.LIGHTCYAN_EX}Recovery of the latest version of chromedriver (dl/cache)...{Style.RESET_ALL}')

    service = Service(ChromeDriverManager(log_level=0).install())
    driver = webdriver.Chrome(service=service, options=options)
    driver.execute_cdp_cmd('Network.setUserAgentOverride', {"userAgent": get_info_config('userAgent')})

    print('')
    print(f'{Fore.LIGHTYELLOW_EX}Starting - Google Dork - ...{Style.RESET_ALL}')
    print('')
    print('----------------------------------------')
    print(f"{Fore.LIGHTGREEN_EX}")

    launch = True
    google_dork_counter = 0
    to_exclude = ''
    wait_values = [5, 3, 6, 7, 10, 9, 4]
    target_size = len(target)
    findings = []

    while True:
        driver.get(f"https://www.google.com/search?hl=fr&as_q=&as_epq=&as_oq=&as_eq={to_exclude}&as_nlo=&as_nhi=&lr=&cr=&as_qdr=all&as_sitesearch=*.{target}&as_occt=any&as_filetype=&tbs=")

        try:
            WebDriverWait(driver, 20).until(EC.presence_of_element_located((By.CLASS_NAME, "tjvcx")))

            if launch:
                driver.find_elements(by=By.CSS_SELECTOR, value="[class='QS5gu sy4vM']")[0].click()

            subdo_current_page = driver.find_elements(by=By.CLASS_NAME, value="tjvcx")

            for i in subdo_current_page:
                subdo = i.text.split(' ')[0]
                if subdo and subdo not in findings:
                    findings.append(subdo)
                    google_dork_counter += 1

                    print(f"{Style.RESET_ALL}[+]{Fore.LIGHTGREEN_EX} {subdo}")

                    if to_exclude:
                        to_exclude += f'+inurl:{subdo_filter(subdo, target_size)}'
                    else:
                        to_exclude += f'inurl:{subdo_filter(subdo, target_size)}'

        except TimeoutException:
            if google_dork_counter == 0:
                print(f'{Style.RESET_ALL}{Fore.LIGHTRED_EX}[x] No unique results found.')

            print(f"{Style.RESET_ALL}")
            print('----------------------------------------')
            print('')
            print(f"Number of unique subdomains found :{Fore.LIGHTGREEN_EX} {google_dork_counter}{Style.RESET_ALL}")
            print('')
            break

        launch = False
        shuffle(wait_values)
        sleep(wait_values[1])

    driver.close()
    return findings