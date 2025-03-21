## Host Discovery

### Ping sweep Nmap

```shell
sudo nmap 10.129.2.0/24 -sn -oA hosts -PE --reason 
```

| `-sn`       | Disables port scanning.                                                  |
| ----------- | ------------------------------------------------------------------------ |
| `-PE`       | Performs the ping scan by using 'ICMP Echo requests' against the target. |
| `--reason`  | Displays the reason for specific result.                                 |

### Ping sweep Metasploit
```
post/multi/gather/ping_sweep
```

### Ping sweep BASH
```shell
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

### Ping sweep CMD
```shell
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

### Ping sweep Powershell
```powershell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```

### Wireshark

```shell
sudo -E wireshark
```

If we are on a host without a GUI (which is typical), we can use [tcpdump](https://linux.die.net/man/8/tcpdump), [net-creds](https://github.com/DanMcInerney/net-creds), and [NetMiner](https://www.netminer.com/en/product/netminer.php), etc., to perform the same functions. We can also use tcpdump to save a capture to a .pcap file, transfer it to another host, and open it in Wireshark.

### tcpdump

```shell
sudo tcpdump -i ens224 
```

### Netdiscover

```shell
sudo netdiscover -i <INTERFACE> -r <IP_RANGE>
```

### dnsrecon

```shell
dnsrecon -d INLANEFREIGHT.LOCAL
```

### NetExec

```shell
nxc smb 10.10.14.0/24
```

## Host and Port Scanning

> [!tip]
> Always scan TCP and UDP

First quick top 1000 ports scan of scope

```shell
sudo nmap --open -oA inlanefreight_ept_tcp_1k -iL scope 
```

Very fast all TCP port SYN scan (for CTF)

```shell
sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG nmap <IP> 
```

UDP port scan

```shell
sudo nmap -p- --open -sU -vvv <IP>
```

If IPv6 known, add `-6`to also scan. There may be not firewalled ports:

```shell
sudo nmap -6 -p- --open -vvv -n -Pn -oG nmap6 dead:beef::1001
```

## Service enumeration

 Deeper scan with scripts and service versions to targeted ports

```shell
sudo nmap -sCV -p <PORTS> -Pn -vvv -oN nmap_target <IP>
```

More agressive scan of all ports

```shell
sudo nmap --open -p- -A -oA inlanefreight_ept_tcp_all_svc -iL scope
```

## Output

We can use this handy Nmap grep [cheatsheet](https://github.com/leonjza/awesome-nmap-grep) to "cut through the noise" and extract the most useful information from the scan.
### hosts and open ports

command
```shell
NMAP_FILE=output.grep

egrep -v "^#|Status: Up" $NMAP_FILE | cut -d' ' -f2,4- | \
sed -n -e 's/Ignored.*//p'  | \
awk '{print "Host: " $1 " Ports: " NF-1; $1=""; for(i=2; i<=NF; i++) { a=a" "$i; }; split(a,s,","); for(e in s) { split(s[e],v,"/"); printf "%-8s %s/%-7s %s\n" , v[2], v[3], v[1], v[5]}; a="" }'
```

output
```shell
Host: 127.0.0.1 Ports: 16
open     tcp/22    ssh
open     tcp/53    domain
open     tcp/80    http
open     tcp/443   https
open     tcp/631   ipp
open     tcp/3306  mysql
open     tcp/4767  unknown
open     tcp/6379
open     tcp/8080  http-proxy
open     tcp/8081  blackice-icecap
open     tcp/9000  cslistener
open     tcp/9001  tor-orport
open     tcp/49152 unknown
open     tcp/49153 unknown
filtered tcp/54695
filtered tcp/58369
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
sudo nmap 10.129.2.28 -p 80 -sV --script vuln 

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

## Firewall and IDS/IPS Evasion 

### ACK-Scan

```shell
-sA --disable-arp-ping
```

Nmap's TCP ACK scan (`-sA`) method is much harder to filter for firewalls and IDS/IPS systems than regular SYN (`-sS`) or Connect scans (`sT`) because they only send a TCP packet with only the `ACK` flag. When a port is closed or open, the host must respond with an `RST` flag. Unlike outgoing connections, all connection attempts (with the `SYN` flag) from external networks are usually blocked by firewalls. However, the packets with the `ACK` flag are often passed by the firewall because the firewall cannot determine whether the connection was first established from the external network or the internal network.

### Decoys

```shell
-D RND:5
```

With this method, Nmap generates various random IP addresses inserted into the IP header to disguise the origin of the packet sent. With this method, we can generate random (`RND`) a specific number (for example: `5`) of IP addresses separated by a colon (`:`). Our real IP address is then randomly placed between the generated IP addresses. In the next example, our real IP address is therefore placed in the second position. Another critical point is that the decoys must be alive. Otherwise, the service on the target may be unreachable due to SYN-flooding security mechanisms.

### Scan by Using Different Source IP

```shell
-S 10.129.2.200 -e tun0
```

### DNS Proxying

`Nmap` still gives us a way to specify DNS servers ourselves (`--dns-server <ns>,<ns>`). This method could be fundamental to us if we are in a demilitarized zone (`DMZ`). The company's DNS servers are usually more trusted than those from the Internet. So, for example, we could use them to interact with the hosts of the internal network. As another example, we can use `TCP port 53` as a source port (`--source-port`) for our scans. If the administrator uses the firewall to control this port and does not filter IDS/IPS properly, our TCP packets will be trusted and passed through.

#### SYN-Scan From DNS Port

```shell
--source-port 53
```

