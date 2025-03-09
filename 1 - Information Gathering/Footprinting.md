# Footrpinting services

## 21 - FTP

Footprinting the Service

```shell
sudo nmap -sV -p21 -sC -A <target_IP>
```

 Anonymous Login

```shell
ftp 10.129.14.136
```

 Recursive Listing

```shell
ls -R
```

 Download a File

```shell
get Important\ Notes.txt
```

 Download All Available Files

```shell
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
```

 Upload a File

```shell
put testupload.txt 
```

## 25 - SMTP

Banner grabbing:

```shell
telnet <FQDN/IP> 25
```

Basic enum:

```shell
nmap -p25 --script smtp-commands <target_IP>
nmap -p25 --script smtp-open-relay <target_IP> -v
```

Enum users:

```shell
Metasploit: auxiliary/scanner/smtp/smtp_enum
smtp-user-enum: smtp-user-enum -M <MODE> -u <USER> -t <IP>
Nmap: nmap --script smtp-enum-users <IP>
```

## 53 - DNS

<https://academy.hackthebox.com/module/112/section/1069>

```shell
dnsenum --dnsserver <nameserver> --enum -p 0 -s 0 -o found_subdomains.txt -f WORDLIST <domain.tld>
```

## 111,2049 - NFS

 Footprinting the Service

```shell
sudo nmap <target_IP> -p111,2049 -sV -sC
sudo nmap --script "nfs*" <target_IP> -sV -p111,2049
```

 Show Available NFS Shares

```shell
showmount -e 10.129.14.128
```

 Mounting NFS Share

```shell
mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
cd target-NFS
tree .

.
└── mnt
    └── nfs
        ├── id_rsa
        ├── id_rsa.pub
        └── nfs.share

2 directories, 3 files
```

Squash

List Contents with Usernames & Group Names

```shell
ls -l mnt/nfs/

total 16
-rw-r--r-- 1 cry0l1t3 cry0l1t3 1872 Sep 25 00:55 cry0l1t3.priv
-rw-r--r-- 1 cry0l1t3 cry0l1t3  348 Sep 25 00:55 cry0l1t3.pub
-rw-r--r-- 1 root     root     1872 Sep 19 17:27 id_rsa
-rw-r--r-- 1 root     root      348 Sep 19 17:28 id_rsa.pub
-rw-r--r-- 1 root     root        0 Sep 19 17:22 nfs.share
```

List Contents with UIDs & GUIDs

```shell
ls -n mnt/nfs/

total 16
-rw-r--r-- 1 1000 1000 1872 Sep 25 00:55 cry0l1t3.priv
-rw-r--r-- 1 1000 1000  348 Sep 25 00:55 cry0l1t3.pub
-rw-r--r-- 1    0 1000 1221 Sep 19 18:21 backup.sh
-rw-r--r-- 1    0    0 1872 Sep 19 17:27 id_rsa
-rw-r--r-- 1    0    0  348 Sep 19 17:28 id_rsa.pub
-rw-r--r-- 1    0    0    0 Sep 19 17:22 nfs.share
```

It is important to note that if the `root_squash` option is set, we cannot edit the `backup.sh` file even as `root`.

Unmounting

```shell
cd ..
sudo umount ./target-NFS
```

## 143,993/110,995 - IMAP/POP3

Enumerate IMAP:

```shell
curl -k 'imaps://<target_IP>' --user robin:robin -v
```

Connect:

```shell
openssl s_client -connect <target_IP>:pop3s
```

```shell
openssl s_client -connect <target_IP>:imaps
```

IMAP Commands:

| **Command**                     | **Description**                                                                                               |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `1 LOGIN username password`     | User's login.                                                                                                 |
| `1 LIST "" *`                   | Lists all directories.                                                                                        |
| `1 CREATE "INBOX"`              | Creates a mailbox with a specified name.                                                                      |
| `1 DELETE "INBOX"`              | Deletes a mailbox.                                                                                            |
| `1 RENAME "ToRead" "Important"` | Renames a mailbox.                                                                                            |
| `1 LSUB "" *`                   | Returns a subset of names from the set of names that the User has declared as being `active` or `subscribed`. |
| `1 SELECT INBOX`                | Selects a mailbox so that messages in the mailbox can be accessed.                                            |
| `1 UNSELECT INBOX`              | Exits the selected mailbox.                                                                                   |
| `1 FETCH <ID> all`              | Retrieves data associated with a message in the mailbox.                                                      |
| `1 FETCH <ID> BODY[TEXT]`            | Retrieves body of message                                                                                                              |
| `1 CLOSE`                       | Removes all messages with the `Deleted` flag set.                                                             |
| `1 LOGOUT`                      | Closes the connection with the IMAP server.                                                                   |

POP3 Commands:

|**Command**|**Description**|
|---|---|
|`USER username`|Identifies the user.|
|`PASS password`|Authentication of the user using its password.|
|`STAT`|Requests the number of saved emails from the server.|
|`LIST`|Requests from the server the number and size of all emails.|
|`RETR id`|Requests the server to deliver the requested email by ID.|
|`DELE id`|Requests the server to delete the requested email by ID.|
|`CAPA`|Requests the server to display the server capabilities.|
|`RSET`|Requests the server to reset the transmitted information.|
|`QUIT`|Closes the connection with the POP3 server.|

## 161,162 - SNMP

```shell
nmap -sUCV -p161,162 <target_IP>
```

Brute force community string:

```shell
onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/snmp.txt <target_IP>
```

Tools:

```shell
snmpwalk -c <community_string> -v1 <target_IP>
```

```shell
snmp-check <target_IP> -c <community_string>
```

## 445 - SMB

 Footprinting the Service

```shell
sudo nmap <target_IP> -sV -sC -p139,445
```

 SMBclient - Connecting to the Share

```shell
smbclient -N -L <target_IP>
```

```shell
smbclient //<target_IP>/notes
```

 Download Files from SMB

```shell
smb: \> get prep-prod.txt 

getting file \prep-prod.txt of size 71 as prep-prod.txt (8,7 KiloBytes/sec) 
(average 8,7 KiloBytes/sec)


smb: \> !ls

prep-prod.txt


smb: \> !cat prep-prod.txt

[] check your code with the templates
[] run code-assessment.py
[] … 
```

 RPCclient

```shell
rpcclient -U "" <target_IP>
```

 Impacket - Samrdump.py

```shell
samrdump.py <target_IP>
```

 SMBmap

```shell
smbmap -H <target_IP>
```

 NetExec(CrackMapExec)

```shell
nxc smb <target_IP> --shares -u '' -p ''
```

 enum4linux-ng

```shell
./enum4linux-ng.py <target_IP> -A
```

smbclient-ng

```shell
smbclientng --host 10.10.11.152 -d 'timelapse.htb' -u 'dsfwf' -p ''
```

## 623 UDP - IPMI

```plain
msf6 auxiliary(scanner/ipmi/ipmi_version) 
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes)
```

## 1433 - MSSQL

```shell
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <target_IP>
```

Metasploit:

```plain
scanner/mssql/mssql_ping
```

Impacket client:

```shell
impacket-mssqlclient <USER>@<target_IP> -windows-auth
```

## 1521 - Oracle TNS

```plain
odat.py
sqlplus
```

## 3306 - MySQL

```shell
sudo nmap <target_IP> -sV -sC -p3306 --script mysql*
```

## Linux Remote Management

SSH

```shell
ssh-audit
```

Rsync

```shell
sudo nmap -sV -p 873 <target_IP>
nc -nv <target_IP> 873
rsync -av --list-only rsync://<target_IP>/dev
```

R-services

```shell
sudo nmap -sV -p 512,513,514 <target_IP>
```

The `hosts.equiv` and `.rhosts` files contain a list of hosts (`IPs` or `Hostnames`) and users that are `trusted` by the local host when a connection attempt is made using `r-commands`.

## Windows Remote Management

RDP

```shell
nmap -sV -sC <target_IP> -p3389 --script rdp*
```

<https://github.com/CiscoCXSecurity/rdp-sec-check>

```shell
xfreerdp /u:<user> /p:"<password>" /v:<FQDN/IP>
```

WinRM

```shell
evil-winrm -i <FQDN/IP> -u <user> -p <password> 
```

WMI

```shell
ipacket-wmiexec <user>:"<password>"@<FQDN/IP> " <system command>"
```
