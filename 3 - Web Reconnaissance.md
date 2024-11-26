## General information

Whatweb
```shell
whatweb -a3 https://www.facebook.com -v
```

Wappalyzer
https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/

wafw00f
```shell
wafw00f -v https://www.tesla.com
```

Nikto

```shell
nikto -h inlanefreight.com -Tuning b
```

## Directories

### Gobuster
```shell
gobuster dir -u <URL> -w <WORDLIST>
```

### Wordlists
```
/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-1.0.txt
```
```
/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
```
```
/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```
## Subdomains

### Ffuf
```shell
ffuf -w <WORDLIST> -u http://<IP address> -H "HOST: FUZZ.target.domain" -fs <RESPONSE_SIZE>
```

### Wordlists
```
/usr/share/wordlists/seclists/Discovery/DNS/namelist.txt
```
```
/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

## Other tools

- [FinalRecon](https://github.com/thewhiteh4t/FinalRecon): A Python-based reconnaissance tool offering a range of modules for different tasks like SSL certificate checking, Whois information gathering, header analysis, and crawling. Its modular structure enables easy customisation for specific needs.
- [Recon-ng](https://github.com/lanmaster53/recon-ng): A powerful framework written in Python that offers a modular structure with various modules for different reconnaissance tasks. It can perform DNS enumeration, subdomain discovery, port scanning, web crawling, and even exploit known vulnerabilities.
- [Feroxbuster](https://github.com/epi052/feroxbuster): A fast, simple, recursive content discovery tool written in Rust.