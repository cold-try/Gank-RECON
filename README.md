# Gank recon. 🏹
Subdomains enumeration, various scans and testing of some vulnerabilities.

<p align="center">
  <img src="https://github.com/cold-try/Gank-RECON/blob/master/media/gank_recon_logo.png" height=250/>
</p>

## ⚙️ Features

- Enumeration of subdomains from a domain name 
- Checking if a subdomain is takeoverable
- Checking if an inaccessible subdomain is bypassable via HTTP verb tampering or custom header
- Port scan
- Recording of results and notifications of changes between each execution of the program (new subdomain/open ports/HTTP code)
- Ergonomic listing of the different active subdomains sorted by HTTP code with the information related to them (open ports, vulnerabilities, changes)

> Possibility to customize certain parameters via the config.json file: personal word list (bruteforce), preferred ports, user-agent..

## 🧪 Logic

<p align="center">
  <img src="https://github.com/cold-try/Gank-RECON/blob/master/media/gank_recon_logic.png" height=700/>
</p>

## ⚡️ Installation

• Python 3 is required
• Install dependencies (preferably in a virtual environment) :
```sh
pip install requirements.txt
```

## 🚀 Launch

• Before starting we need to get some API keys, this is not mandatory but highly recommended to maximize our results.

| Service | Website | Is it free? |
| ------ | ------ | ------ |
| Binary Edge | https://www.binaryedge.io | yes
| Security Trails | https://securitytrails.com | yes
| Censys | https://censys.io | yes

Go to the config.json file and enter your API keys there.

• You can modify the values contained in the config.json file: the user agent, the number of threads, the list used for the bruteforce (the default list contains 10,000 lines) or modify the port lists by your preferred ports.

• To start the program, go to the root of the directory and run the command : 
```sh
python3 core.py
```

<p align="center">
  <img src="https://github.com/cold-try/Gank-RECON/blob/master/media/output_exmpl.png" height=500/>
</p>

## 🚨 Disclaimer 

• The objective of this tool is preventive and aims to secure websites by detecting potential vulnerabilities. The use of this tool on a website without the explicit agreement of its owner is strictly prohibited.

• When using this tool on a bug bounty program, please be sure to read the policy of the targeted platform. Some companies do not accept active scans, in this case please limit yourself to the subdomain listing and do not enable options that go against this policy.


## 🦾 Support me

If you want to support my work and encourage me in the creation of security tools, don't hesitate to buy me a coffee here : 

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/zhero)

## License

MIT
