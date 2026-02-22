# KaliForge II

Bootstrap a security-focused Kali Linux VM with profiled tool sets, parallel GitHub downloads, and system hardening.

![KaliForge II](assets/KaliForgeIILogo.png)

## Quick Start

```bash
git clone https://github.com/tikket1/KaliForgeII.git
cd KaliForgeII
sudo python3 kaliforge2-unified.py
```

The TUI wizard walks through username, SSH, profile selection, and optional KDE/GitHub configuration, then runs the bootstrap.

To run the shell script directly (headless):

```bash
export USER_NAME=myuser PROFILE=standard SSH_PORT=2222
sudo -E bash kaliforge2.sh
```

## Security Profiles

| Profile    | Use Case                        | Includes                                                        |
|------------|--------------------------------|-----------------------------------------------------------------|
| `minimal`  | Lightweight recon, small VPS   | nmap, netcat, curl, wget, jq                                   |
| `webapp`   | Web app testing, bug bounty    | gobuster, ffuf, sqlmap, burpsuite, nikto, nuclei                |
| `internal` | Internal/AD pentesting         | crackmapexec, impacket, bloodhound, responder, smbclient        |
| `cloud`    | Cloud infra security           | awscli, azure-cli, gcloud, kubectl, terraform                  |
| `standard` | General pentesting (default)   | Balanced mix of web, network, and system tools                  |
| `heavy`    | Full arsenal                   | Everything above + metasploit, hashcat, john, volatility3, C2   |

## Tool Directory Structure

```
~/PentestTools/
├── Recon/{DNS,Web,Network,OSINT,Subdomain}
├── WebApp/{Scanners,Proxies,Fuzzing,SQLi,XSS}
├── Network/{Scanning,Exploitation,MITM,Wireless}
├── PrivEsc/{Linux,Windows/{PrintSpoofer,GodPotato}}
├── ActiveDirectory/{Enumeration,BloodHound,Kerberos,SharpHound}
├── Pivoting/{Linux,Windows}
├── Shells/{Reverse,WebShells,Generators}
├── C2/{Cobalt,Empire,Sliver}
├── Cloud/{AWS,Azure,GCP}
├── PostExploit/{Persistence,Lateral,Exfiltration}
├── Reports/{Templates,Screenshots,Evidence}
├── Wordlists/{Passwords,Usernames,Directories}
└── Binaries/{Windows,Linux}
```

## Security Hardening

The bootstrap script applies the following hardening automatically:

- **SSH**: Key-only auth, PAM disabled, custom port, AllowUsers restricted
- **Firewall**: UFW deny-incoming by default, optional CIDR allowlists for SSH
- **Fail2ban**: 2-hour bans, 5 max retries, systemd backend
- **Sysctl**: rp_filter, syncookies, kptr_restrict, dmesg_restrict, optional IPv6 disable
- **Account lockdown**: Root and default kali accounts locked
- **Sudo**: 5-minute timeout, 3 password tries, input/output logging
- **Services disabled**: avahi, cups, rpcbind, neo4j
- **Unattended upgrades**: Kali rolling origin, auto-security-patches

## Security Modes (TUI)

After initial setup, the TUI provides runtime mode switching:

- **Hardened** -- Deny all incoming+outgoing except DNS/HTTP/HTTPS/NTP
- **Honeypot** -- Allow all traffic for threat monitoring
- **Stealth** -- Deny incoming, minimal logging, tor/proxychains ready
- **Pentest** -- IP forwarding enabled, postgresql/apache2 for tool support

## Configuration

All settings are driven by environment variables (or set via the TUI):

| Variable                 | Default    | Description                          |
|--------------------------|------------|--------------------------------------|
| `USER_NAME`              | `tikket`   | Non-root user to create              |
| `SSH_PORT`               | `2222`     | SSH listen port                      |
| `PROFILE`                | `standard` | Tool profile (see above)             |
| `PUBKEY`                 | *(empty)*  | SSH public key; SSH disabled if empty |
| `INSTALL_KDE`            | `true`     | Install KDE desktop + SDDM           |
| `GITHUB_TOKEN`           | *(empty)*  | GitHub PAT for higher API rate limits |
| `ALLOWLIST_CIDR`         | *(empty)*  | Comma-separated CIDRs for SSH access |
| `DISABLE_IPV6`           | `false`    | Disable IPv6 via sysctl              |
| `MAX_PARALLEL_DOWNLOADS` | `4`        | Concurrent GitHub release downloads  |

## Files

| File                            | Purpose                              |
|---------------------------------|--------------------------------------|
| `kaliforge2-unified.py`        | Ncurses TUI for configuration        |
| `kaliforge2.sh`                | Consolidated bash bootstrapper       |
| `kaliforge2_ascii_terminal.txt`| ASCII art header for TUI             |
| `assets/KaliForgeIILogo.png`   | Logo                                 |

## Legal Disclaimer

This tool is for **authorized security testing and education only**. Users are responsible for compliance with all applicable laws. Use only on systems you own or have explicit written permission to test.

## License

MIT License. See [LICENSE](LICENSE).
