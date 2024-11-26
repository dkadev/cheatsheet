## Host Discovery

Ping sweep Nmap

```shell
sudo nmap 10.129.2.18 -sn -oA host -PE --reason 
```

| **Scanning Options** | **Description**                                                          |
| -------------------- | ------------------------------------------------------------------------ |
| `10.129.2.18`        | Performs defined scans against the target.                               |
| `-sn`                | Disables port scanning.                                                  |
| `-oA host`           | Stores the results in all formats starting with the name 'host'.         |
| `-PE`                | Performs the ping scan by using 'ICMP Echo requests' against the target. |
| `--reason`           | Displays the reason for specific result.                                 |

Ping sweep Metasploit
```
post/multi/gather/ping_sweep
```

Ping sweep BASH
```shell
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

Ping sweep CMD
```shell
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

Ping sweep Powershell
```powershell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```

Wireshark

```shell
sudo -E wireshark
```

If we are on a host without a GUI (which is typical), we can use [tcpdump](https://linux.die.net/man/8/tcpdump), [net-creds](https://github.com/DanMcInerney/net-creds), and [NetMiner](https://www.netminer.com/en/product/netminer.php), etc., to perform the same functions. We can also use tcpdump to save a capture to a .pcap file, transfer it to another host, and open it in Wireshark.

tcpdump

```shell
sudo tcpdump -i ens224 
```

Netdiscover

```shell
sudo netdiscover -i <INTERFACE> -r <IP_RANGE>
```

dnsrecon

```shell
dnsrecon -d INLANEFREIGHT.LOCAL
```

## Host and Port Scanning

> [!tip]
> Always scan TCP and UDP

 Fast open TCP port scan

```shell
sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG nmap <IP> 
```

UDP port scan

```shell
sudo nmap -p- --open -sU -vvv <IP>
```

## Service enumeration

 Deeper scan with scripts and service versions

```shell
nmap -sCV -p <PORTS> -Pn -vvv -oN nmap_target <IP>
```

## NSE (Nmap Scripting Engine)
Default Scripts

```shell
sudo nmap <target> -sC
```

Specific Scripts Category

```shell
sudo nmap <target> --script <category>
```

Defined Scripts

```shell
sudo nmap <target> --script <script-name>,<script-name>,...
```

## Vulnerability Assessment

Nmap - Vuln Category

```shell
fango@htb[/htb]$ sudo nmap 10.129.2.28 -p 80 -sV --script vuln 

Nmap scan report for 10.129.2.28
Host is up (0.036s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-enum:
|   /wp-login.php: Possible admin folder
|   /readme.html: Wordpress version: 2
|   /: WordPress version: 5.3.4
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|_  /readme.html: Interesting, a readme.
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-wordpress-users:
| Username found: admin
|_Search stopped at ID #25. Increase the upper limit if necessary with 'http-wordpress-users.limit'
| vulners:
|   cpe:/a:apache:http_server:2.4.29:
|     	CVE-2019-0211	7.2	https://vulners.com/cve/CVE-2019-0211
|     	CVE-2018-1312	6.8	https://vulners.com/cve/CVE-2018-1312
|     	CVE-2017-15715	6.8	https://vulners.com/cve/CVE-2017-15715
<SNIP>
```

|**Scanning Options**|**Description**|
|---|---|
|`10.129.2.28`|Scans the specified target.|
|`-p 80`|Scans only the specified port.|
|`-sV`|Performs service version detection on specified ports.|
|`--script vuln`|Uses all related scripts from specified category.|

## Other options and tools

Target and exclusion files:

```shell
-iL hosts --excludefile no_hosts
```

Use NSE scripts:

```shell
--script "service*"
```

Naabu
httpx
