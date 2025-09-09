# KaliForge II

**Next-generation security environment setup with parallel downloads, real-time monitoring, and intelligent tool management.**

![KaliForge II](assets/KaliForgeIILogo.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/Security-Hardened-green.svg)](https://github.com/yourusername/KaliForgeII)

## What is KaliForge II?

KaliForge II transforms your Kali Linux setup from a slow, manual process into a fast, intelligent, and secure environment. Think of it as the evolution of penetration testing infrastructure - where your tools are organized, your downloads are lightning-fast, and your security posture adapts to your needs.

**The Problem**: Traditional Kali setups are slow (15+ minute downloads), disorganized, and use hardcoded configurations that compromise security.

**The Solution**: KaliForge II delivers parallel downloads (3x faster), smart tool organization, and dynamic security modes that adapt to your workflow.

## Core Features

### Lightning-Fast Setup
- **Parallel Downloads**: 66% faster installation using concurrent GitHub releases
- **Real-time Progress**: Live progress bars showing exactly what's happening
- **Smart Fallback**: Automatically handles failures and network issues
- **Optimized Profiles**: Only install what you need for your specific work

### Intelligent Security Modes
Switch your entire security posture instantly:
- **Hardened**: Minimal attack surface for production environments  
- **Honeypot**: Open monitoring for threat research
- **Stealth**: Tor-enabled anonymity for sensitive operations
- **Pentest**: Optimized configuration for active testing

### Professional Tool Management
- **Structured Organization**: No more hunting through random directories
- **Latest Versions**: Always pulls the newest releases from GitHub
- **Cross-Platform Binaries**: Linux and Windows versions where available
- **Smart Categorization**: Tools organized by attack methodology

## Quick Start

**Prerequisites**: Kali Linux, root access, Python 3.6+

```bash
git clone https://github.com/yourusername/KaliForgeII.git
cd KaliForgeII
chmod +x kaliforge2-unified.py
sudo ./kaliforge2-unified.py
```

The unified interface walks you through everything:
1. User configuration (no more hardcoded "tikket" nonsense)
2. Profile selection based on your work type
3. Security mode selection  
4. Lightning-fast parallel installation
5. Ready to hack in minutes, not hours

## Security Profiles Explained

### Minimal Profile
Perfect for resource-constrained environments or quick reconnaissance tasks.
- Core networking tools (nmap, netcat, curl)
- Basic utilities and minimal footprint
- Ideal for: Initial scoping, lightweight VPS deployments

### Web Application Profile  
Everything you need for web app security testing.
- Directory busters, vulnerability scanners, proxy tools
- CMS-specific scanners, SQLi tools, XSS utilities
- Ideal for: Bug bounty hunting, web application assessments

### Internal Network Profile
Built for internal penetration testing and Active Directory environments.
- SMB tools, Kerberos attacks, BloodHound integration
- Network responders, privilege escalation tools
- Ideal for: Corporate red teams, internal assessments

### Cloud Security Profile
Modern cloud infrastructure security testing.
- AWS/Azure/GCP CLI tools, container scanners
- Kubernetes security tools, IAM testing utilities  
- Ideal for: Cloud security assessments, DevSecOps

### Standard Profile
The balanced choice for general penetration testing.
- Combination of web, network, and system tools
- Metasploit Framework, database tools
- Ideal for: Most penetration testers, general assessments

### Heavy Profile  
The complete arsenal for comprehensive security work.
- Everything from other profiles plus advanced frameworks
- Password cracking suites, forensics tools, C2 frameworks
- Ideal for: Advanced red teams, comprehensive assessments

## How It Works Under the Hood

### Parallel Download System
Instead of downloading tools one-by-one (slow), KaliForge II:
1. **Batches Downloads**: Groups related tools for parallel execution
2. **Progress Tracking**: JSON-based real-time status updates
3. **Error Recovery**: Automatic retries with exponential backoff
4. **Smart Fallback**: Falls back to sequential mode if needed

**Performance Impact**: What used to take 15 minutes now takes 5 minutes.

### Security Mode Architecture
Each mode automatically reconfigures:
- **UFW Firewall Rules**: Specific iptables configurations
- **System Services**: Starts/stops relevant daemons  
- **Network Parameters**: IP forwarding, redirect handling
- **Monitoring Setup**: Appropriate logging and audit trails

### Tool Organization Philosophy
```
PentestTools/
├── Recon/{DNS,Web,Network,OSINT}/     # Information gathering
├── WebApp/{Scanners,Proxies,Fuzzing}/ # Web application testing  
├── Network/{Scanning,Exploitation}/   # Network-level attacks
├── PrivEsc/{Linux,Windows}/           # Privilege escalation
├── ActiveDirectory/{Enumeration}/     # AD-specific tools
├── Pivoting/{Linux,Windows}/          # Lateral movement
├── Shells/{Reverse,Generators}/       # Shell management
├── C2/{Sliver,Empire}/               # Command & control
└── Cloud/{AWS,Azure,GCP}/            # Cloud security tools
```

## Advanced Usage

### Real-time Monitoring
```bash
# Watch downloads in real-time
python3 kaliforge2_progress_monitor.py --watch

# Generate progress reports
python3 kaliforge2_progress_monitor.py --report

# Get raw JSON status
python3 kaliforge2_progress_monitor.py --json
```

### Security Mode Switching
```bash
# Launch unified interface
sudo ./kaliforge2-unified.py

# Navigate to "Security Mode Switcher"
# Choose your mode based on current needs
# System automatically reconfigures
```

### Custom Configurations
The system is built for customization:
- **GitHub Token**: Add your token for higher API limits
- **Custom Profiles**: Modify tool selections per profile
- **Network Settings**: Adjust firewall rules and port configurations

## What Makes This Different

**Traditional Kali Setup**:
- Sequential downloads (slow)
- No progress visibility  
- Hardcoded configurations
- Poor tool organization
- No security mode switching

**KaliForge II**:
- Parallel downloads (3x faster)
- Real-time progress monitoring
- Dynamic configuration
- Intelligent tool organization  
- Instant security mode switching

## Real-World Applications

### Bug Bounty Hunting
Select "webapp" profile, get instant access to:
- gobuster, ffuf, nuclei for discovery
- sqlmap, XSStrike for exploitation
- BurpSuite, OWASP ZAP for manual testing
- All organized in logical directories

### Corporate Red Teams
Select "internal" profile for immediate AD testing:
- crackmapexec for SMB enumeration
- impacket suite for various attacks
- BloodHound for attack path analysis
- PowerShell tools for Windows environments

### Cloud Security  
Select "cloud" profile for modern infrastructure:
- Multi-cloud CLI tools (AWS, Azure, GCP)
- Container security scanners
- Kubernetes penetration testing tools
- Infrastructure-as-code security tools

## Performance Benchmarks

**Legacy Sequential Downloads**:
- Heavy profile: ~15 minutes
- Standard profile: ~8 minutes
- Limited progress visibility

**KaliForge II Parallel System**:
- Heavy profile: ~5 minutes (66% improvement)
- Standard profile: ~3 minutes (62% improvement)
- Real-time progress with failure recovery

## Contributing

We welcome contributions that improve setup speed, tool organization, or security posture.

```bash
git clone https://github.com/yourusername/KaliForgeII.git
cd KaliForgeII

# Test your changes
python3 kaliforge2-unified.py

# Submit pull requests for review
```

## Security Considerations

KaliForge II is designed for **authorized security testing only**:

- **Defensive Use**: Built for legitimate penetration testing and security research
- **Proper Authorization**: Only use on systems you own or have explicit permission to test
- **Logging**: All activities are logged to `/var/log/kaliforge2/`  
- **Hardened Defaults**: SSH key-only authentication, fail2ban, custom ports

## Technical Details

**Core Components**:
- `kaliforge2-unified.py`: Main ncurses interface with progress display
- `github_release_manager_parallel.sh`: Parallel download engine  
- `kaliforge2_progress_monitor.py`: Real-time progress tracking
- `kaliforge2.sh`: Enhanced bootstrap with parallel integration

**System Requirements**:
- Kali Linux (preferred) or Ubuntu/Debian
- Python 3.6+ with curses support
- Root privileges for system configuration
- Network access for GitHub API and downloads

## License

MIT License - Built for the security community.

## Legal Disclaimer  

This tool is designed for **defensive security and authorized testing only**. Users are responsible for ensuring compliance with all applicable laws and regulations. Use only on systems you own or have explicit written permission to test.

---

**KaliForge II - Where security setup meets performance**  
*Professional penetration testing infrastructure in minutes, not hours*