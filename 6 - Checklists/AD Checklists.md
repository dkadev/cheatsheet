### AD Unauthenticated

1. **Network Discovery**
   - Identify domain controllers and other critical servers.
   - Enumerate open ports and services.

2. **DNS Enumeration**
   - Perform DNS zone transfers if possible.
   - Use tools like `nslookup`, `dig`, or `dnsrecon`.

3. **LDAP Enumeration**
   - Attempt anonymous LDAP binds.
   - Enumerate users, groups, and other objects.

4. **SMB Enumeration**
   - Check for null sessions.
   - Enumerate shares and access permissions.

5. **Kerberos Enumeration**
   - Identify SPNs using tools like `kerbrute`.
   - Check for misconfigurations like unconstrained delegation.

6. **Password Policy**
   - Identify password policies and account lockout policies.

### AD Authenticated

1. **Network Mapping**
   - Use tools like `nmap` to map the network from an authenticated perspective.

2. **LDAP Queries**
   - Perform detailed LDAP queries to gather information about users, groups, and policies.

3. **Group Policy Enumeration**
   - Enumerate Group Policy Objects (GPOs) and their settings.

4. **Kerberos Attacks**
   - Perform Kerberoasting to extract service tickets.
   - Attempt AS-REP roasting if pre-authentication is disabled.

5. **SMB and File Shares**
   - Access and enumerate file shares.
   - Look for sensitive information in shared files.

6. **Local Privilege Escalation**
   - Check for local admin rights on machines.
   - Look for misconfigurations or vulnerable software.

### AD Privileged Auth on Machine

1. **Domain Admin Enumeration**
   - Identify all domain admin accounts and their privileges.

2. **Credential Dumping**
   - Use tools like `mimikatz` to dump credentials from memory.
   - Extract hashes for offline cracking.

3. **Lateral Movement**
   - Use tools like `PsExec`, `WMI`, or `RDP` for lateral movement.
   - Identify and exploit trust relationships.

4. **Persistence Mechanisms**
   - Set up persistence using scheduled tasks, services, or startup scripts.

5. **Active Directory Database**
   - Access and extract the NTDS.dit file if possible.
   - Analyze the database for sensitive information.

6. **Privilege Escalation**
   - Look for opportunities to escalate privileges further, such as exploiting vulnerable services or misconfigurations.
