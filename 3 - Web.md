# Web

## Information gathering

Whatweb

```shell
whatweb -a3 https://www.facebook.com -v
```

Wappalyzer
<https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/>

wafw00f

```shell
wafw00f -v https://www.tesla.com
```

Nikto

```shell
nikto -h inlanefreight.com -Tuning b
```

## Enumeration

### Directories

Ffuf

```shell
ffuf -w <WORDLIST>:FUZZ -ic -v -u http://<IP address>/FUZZ -ac -recursion
```

- `-ic`: Ignores commented lines in wordlist when fuzzing.
- `-v`: Verbose output, printing full URL and redirect location (if any) with the results.
- `-ac`: Automatically calibrates the response filtering, which helps in identifying false positives.
- `-recursion`: Enables recursive fuzzing, meaning that if a directory is found, `ffuf` will continue to fuzz within that directory.

Gobuster

```shell
gobuster dir -u <URL> -w <WORDLIST>
```

Feroxbuster

```shell
feroxbuster --url http://10.13.38.11/ -w ../wordlist.txt
```

Wordlists

```plain
/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-1.0.txt
```

```plain
/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
```

```plain
/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```

### Subdomains

Ffuf

```shell
ffuf -w <WORDLIST> -u http://<IP address> -H "HOST: FUZZ.target.domain" -fs <RESPONSE_SIZE>
```

Wordlists

```plain
/usr/share/wordlists/seclists/Discovery/DNS/namelist.txt
```

```plain
/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

### Other tools

- [FinalRecon](https://github.com/thewhiteh4t/FinalRecon): A Python-based reconnaissance tool offering a range of modules for different tasks like SSL certificate checking, Whois information gathering, header analysis, and crawling. Its modular structure enables easy customisation for specific needs.
- [Recon-ng](https://github.com/lanmaster53/recon-ng): A powerful framework written in Python that offers a modular structure with various modules for different reconnaissance tasks. It can perform DNS enumeration, subdomain discovery, port scanning, web crawling, and even exploit known vulnerabilities.
- [Feroxbuster](https://github.com/epi052/feroxbuster): A fast, simple, recursive content discovery tool written in Rust.

## Vulnerabilities

### HTTP Verb Tampering

An HTTP Verb Tampering attack exploits web servers that accept many HTTP verbs and methods. This can be exploited by sending malicious requests using unexpected methods, which may lead to bypassing the web application's authorization mechanism or even bypassing its security controls against other web attacks. HTTP Verb Tampering attacks are one of many other HTTP attacks that can be used to exploit web server configurations by sending malicious HTTP requests.

### Insecure Direct Object References (IDOR)

IDOR is among the most common web vulnerabilities and can lead to accessing data that should not be accessible by attackers. What makes this attack very common is essentially the lack of a solid access control system on the back-end. As web applications store users' files and information, they may use sequential numbers or user IDs to identify each item. Suppose the web application lacks a robust access control mechanism and exposes direct references to files and resources. In that case, we may access other users' files and information by simply guessing or calculating their file IDs.

### XML External Entity (XXE) Injection

Many web applications process XML data as part of their functionality. Suppose a web application utilizes outdated XML libraries to parse and process XML input data from the front-end user. In that case, it may be possible to send malicious XML data to disclose local files stored on the back-end server. These files may be configuration files that may contain sensitive information like passwords or even the source code of the web application, which would enable us to perform a Whitebox Penetration Test on the web application to identify more vulnerabilities. XXE attacks can even be leveraged to steal the hosting server's credentials, which would compromise the entire server and allow for remote code execution.
