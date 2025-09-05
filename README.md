<div align="center">
  <img src="assets/KaliForgeIILogo.png" alt="KaliForge II Logo" width="600">
</div>

# 🚀 KaliForge II - Next-Generation Kali Linux Environment Setup

**KaliForge II** is a security-first, comprehensive Kali Linux environment manager that combines **enhanced password management**, **comprehensive logging**, **structured tool organization**, and **workflow-specific profiles**.

## 🔥 What's New in KaliForge II

### 🔐 Enhanced Password Management
- **Prominent password display** with security warnings
- **Secure password logging** with 600 permissions
- **Auto-expiring credential files** (5-minute security deletion)
- **Interactive password reset** for existing users

### 📊 Comprehensive Logging System
```
/var/log/kaliforge2/
├── kaliforge2_TIMESTAMP.log          # Main installation log
├── passwords_TIMESTAMP.log           # Secure password storage (600)
├── install_summary_TIMESTAMP.log     # Installation progress
├── errors_TIMESTAMP.log              # Error tracking
├── INSTALLATION_COMPLETE_TIMESTAMP.txt # Final summary
└── README.txt                         # Log directory guide
```

### 🛡️ Security-First Design
- SSH hardening (key-only, custom port, no PAM)
- UFW firewall with restrictive rules
- Fail2ban intrusion prevention
- System hardening (sysctl, service lockdown)
- User privilege management

### 🗂️ Structured Tool Organization
```
PentestTools/
├── Recon/{DNS,Web,Network,OSINT,Subdomain}/
├── WebApp/{Scanners,Proxies,Fuzzing,SQLi,XSS}/
├── Network/{Scanning,Exploitation,MITM,Wireless}/
├── PrivEsc/{Linux,Windows}/
├── ActiveDirectory/{Enumeration,BloodHound,Kerberos}/
├── Pivoting/{Linux,Windows}/
├── Shells/{Reverse,WebShells,Generators}/
├── C2/{Cobalt,Empire,Sliver}/
├── Cloud/{AWS,Azure,GCP}/
├── Reports/{Templates,Screenshots,Evidence}/
├── Wordlists/{Passwords,Usernames,Directories}/
└── Binaries/{Windows,Linux}/
```

## 🎯 Workflow Profiles

| Profile | Description | Key Tools | Use Case |
|---------|-------------|-----------|----------|
| **minimal** | Lightweight essentials | nmap, netcat, curl, jq | Basic recon, low-resource environments |
| **webapp** | Web application testing | gobuster, sqlmap, BurpSuite, nuclei, ffuf | Web app pentesting, bug bounties |
| **internal** | Internal network testing | crackmapexec, impacket, BloodHound, responder | Corporate network assessments |
| **cloud** | Cloud security testing | awscli, kubectl, terraform, docker | Cloud penetration testing |
| **standard** | Balanced general toolkit | Mix of network, web, and exploitation tools | General penetration testing |
| **heavy** | Full security arsenal | Everything + Metasploit, volatility, hashcat | Comprehensive security assessments |

## 🚀 Quick Start

### Interactive Setup (Recommended)
```bash
sudo ./kaliforge2-tui.sh
```

### Direct Installation
```bash
export PROFILE="webapp"              # Choose your profile
export USER_NAME="pentester"         # Set username  
export PUBKEY="ssh-rsa AAAAB3..."    # Your SSH public key
export SSH_PORT="2222"              # SSH port
export GITHUB_TOKEN="ghp_xxxx"      # Optional: GitHub API token

sudo ./kaliforge2.sh
```

## 🔧 Configuration Options

### Core Settings
```bash
USER_NAME="tikket"           # Pentesting user account
SSH_PORT="2222"             # Custom SSH port
PROFILE="standard"          # Installation profile  
INSTALL_KDE="true"          # Desktop environment
PUBKEY=""                   # SSH public key for access
GITHUB_TOKEN=""             # GitHub API token (recommended)
ALLOWLIST_CIDR=""          # IP allowlist for SSH access
DISABLE_IPV6="false"       # IPv6 configuration
```

### Password Management
- **32-character secure passwords** with mixed character sets
- **Interactive password display** with prominent warnings
- **Secure logging** to `/var/log/kaliforge2/passwords_*.log`
- **Auto-cleanup** of temporary credential files
- **Password reset option** for existing users

## 📋 Installation Output

### Password Display
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                            🔐 KALIFORGE II CREDENTIALS 🔐                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Username: pentester                                                         ║
║  Password: A8k#mX9@pL2$nR5*qW7+vB3!                                         ║
║                                                                              ║
║  ⚠️  IMPORTANT: Save this password in a secure location!                     ║
║                                                                              ║
║  💾 Password also saved to: /var/log/kaliforge2/passwords_20241205_143022.log║
║                                                                              ║
║  🚨 This file will be deleted in 5 minutes for security.                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### Final Summary
```
================== KALIFORGE II COMPLETE ===================
 👤 User: pentester
 ⚙️  Profile: webapp
 📁 Tools: /home/pentester/PentestTools
 🔐 SSH: ENABLED (Port: 2222)
 📋 Logs: /var/log/kaliforge2
 💾 Password: /var/log/kaliforge2/passwords_20241205_143022.log

 🚀 Quick commands:
    tools          # Navigate to toolkit
    cd /home/pentester/PentestTools  # Direct navigation
    sudo -u pentester -i  # Switch to pentest user
===========================================================
```

## 🤖 GitHub Integration

KaliForge II automatically downloads the latest tool releases:

### Privilege Escalation Tools
- **PEASS-ng** (LinPEAS, WinPEAS) - Linux and Windows enumeration
- **pspy** - Linux process monitoring without root
- **PrintSpoofer, GodPotato** - Windows privilege escalation

### Tunneling & Pivoting
- **Chisel** - Fast TCP/UDP tunnel (Linux/Windows x86/x64)

### Active Directory Tools
- **BloodHound, SharpHound** - AD attack path analysis
- **PKINITtools, ntlm_theft** - Kerberos and NTLM attacks

### Shell & Post-Exploitation
- **Penelope, Nishang, HoaxShell** - Various shell tools
- **PowerShell obfuscation tools**

## 🛠️ Files Overview

- **`kaliforge2.sh`** - Main installation script
- **`kaliforge2-tui.sh`** - Interactive configuration interface
- **`github_release_manager.sh`** - GitHub release automation
- **`kali_bootstrapper.sh`** - Original security-focused foundation
- **`README.md`** - This documentation

## 🔒 Security Features

### SSH Hardening
✅ Key-only authentication (no passwords)  
✅ Custom port (default: 2222)  
✅ Root login disabled  
✅ PAM authentication disabled  
✅ Fail2ban monitoring  

### System Hardening  
✅ UFW firewall with restrictive rules  
✅ Audit logging (rsyslog, auditd)  
✅ Kernel security parameters (sysctl)  
✅ Service lockdown (unnecessary services disabled)  
✅ User account security  

### Log Security
✅ Secure password storage (600 permissions)  
✅ Timestamped log files  
✅ Comprehensive error tracking  
✅ Installation audit trail  

## 🆚 Comparison Matrix

| Feature | Original Kali | KaliForge I | **KaliForge II** |
|---------|---------------|-------------|------------------|
| Security hardening | ❌ | ❌ | ✅ |
| Tool organization | ❌ | ✅ | ✅ |
| Password management | ❌ | ❌ | **✅** |
| Comprehensive logging | ❌ | ❌ | **✅** |
| Workflow profiles | ❌ | ✅ | ✅ |
| GitHub integration | ❌ | ✅ | ✅ |
| Interactive setup | ❌ | ❌ | **✅** |
| Application config | ❌ | ✅ | ✅ |

## 🎯 Use Cases

### 🔍 Bug Bounty Hunters
```bash
export PROFILE="webapp"
sudo ./kaliforge2-tui.sh
```
Gets you: gobuster, sqlmap, BurpSuite, nuclei, ffuf, and organized web testing toolkit.

### 🏢 Corporate Penetration Testers  
```bash
export PROFILE="internal"
sudo ./kaliforge2-tui.sh
```
Gets you: crackmapexec, impacket, BloodHound, responder, and AD testing tools.

### ☁️ Cloud Security Engineers
```bash
export PROFILE="cloud" 
sudo ./kaliforge2-tui.sh
```
Gets you: AWS/Azure/GCP CLI tools, kubectl, terraform, container security tools.

### 🛡️ Red Team Operators
```bash
export PROFILE="heavy"
sudo ./kaliforge2-tui.sh  
```
Gets you: Full arsenal including Metasploit, C2 frameworks, password cracking, forensics.

## 🤝 Contributing

KaliForge II is designed for the security community. Contributions welcome:

- 🔧 Additional workflow profiles
- 🛠️ New tool integrations  
- 🔒 Security improvements
- 📚 Documentation enhancements
- 🐛 Bug reports and fixes

## ⚖️ License & Disclaimer

Built for **defensive security and authorized testing only**. Users are responsible for compliance with all applicable laws and regulations. Only use on systems you own or have explicit written permission to test.

---

### 🏗️ Architecture Philosophy

KaliForge II follows the principle: **"Security first, usability second, but both excellently executed."**

This means every feature prioritizes security hardening while maintaining an exceptional user experience for penetration testing workflows.