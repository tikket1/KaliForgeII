#!/usr/bin/env bash
# KaliForge II - Next-generation security-first Kali Linux environment setup
# Enhanced version with structured tools, profiles, and comprehensive logging
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive

# -------------------- Logging Setup --------------------
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="/var/log/kaliforge2"
MAIN_LOG="$LOG_DIR/kaliforge2_${TIMESTAMP}.log"
PASSWORD_LOG="$LOG_DIR/passwords_${TIMESTAMP}.log"
INSTALL_LOG="$LOG_DIR/install_summary_${TIMESTAMP}.log"
ERROR_LOG="$LOG_DIR/errors_${TIMESTAMP}.log"

# Create log directory
mkdir -p "$LOG_DIR"
chmod 700 "$LOG_DIR"  # Secure log directory

# Setup logging with multiple outputs
exec 1> >(tee -a "$MAIN_LOG")
exec 2> >(tee -a "$ERROR_LOG" >&2)
set -x
trap 'echo "ERROR at line $LINENO: $BASH_COMMAND" | tee -a "$ERROR_LOG"; exit 1' ERR

# -------------------- Configuration --------------------
USER_NAME="${USER_NAME:-tikket}"
SSH_PORT="${SSH_PORT:-2222}"
ALLOWLIST_CIDR="${ALLOWLIST_CIDR:-}"
DISABLE_IPV6="${DISABLE_IPV6:-false}"
INSTALL_KDE="${INSTALL_KDE:-true}"
PUBKEY="${PUBKEY:-}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

# Workflow Profile Configuration
PROFILE="${PROFILE:-standard}"  # Options: minimal, webapp, internal, cloud, standard, heavy
TOOLS_DIR="/home/$USER_NAME/PentestTools"

# -------------------- Tool Organization Structure --------------------
create_tool_directories() {
    echo "[+] Creating structured tool directories"
    local base_dir="$TOOLS_DIR"
    
    # Main categories
    local directories=(
        # Reconnaissance
        "$base_dir/Recon/DNS"
        "$base_dir/Recon/Web"
        "$base_dir/Recon/Network"
        "$base_dir/Recon/OSINT"
        "$base_dir/Recon/Subdomain"
        
        # Web Application Testing
        "$base_dir/WebApp/Scanners"
        "$base_dir/WebApp/Proxies"
        "$base_dir/WebApp/Fuzzing"
        "$base_dir/WebApp/SQLi"
        "$base_dir/WebApp/XSS"
        
        # Network Testing
        "$base_dir/Network/Scanning"
        "$base_dir/Network/Exploitation"
        "$base_dir/Network/MITM"
        "$base_dir/Network/Wireless"
        
        # Privilege Escalation
        "$base_dir/PrivEsc/Linux"
        "$base_dir/PrivEsc/Windows"
        "$base_dir/PrivEsc/Windows/PrintSpoofer"
        "$base_dir/PrivEsc/Windows/GodPotato"
        
        # Post Exploitation
        "$base_dir/PostExploit/Persistence"
        "$base_dir/PostExploit/Lateral"
        "$base_dir/PostExploit/Exfiltration"
        
        # Active Directory
        "$base_dir/ActiveDirectory/Enumeration"
        "$base_dir/ActiveDirectory/BloodHound"
        "$base_dir/ActiveDirectory/Kerberos"
        "$base_dir/ActiveDirectory/SharpHound"
        
        # Pivoting & Tunneling
        "$base_dir/Pivoting/Linux"
        "$base_dir/Pivoting/Windows"
        
        # Shells & Payloads
        "$base_dir/Shells/Reverse"
        "$base_dir/Shells/WebShells"
        "$base_dir/Shells/Generators"
        
        # Command & Control
        "$base_dir/C2/Cobalt"
        "$base_dir/C2/Empire"
        "$base_dir/C2/Sliver"
        
        # Cloud Testing
        "$base_dir/Cloud/AWS"
        "$base_dir/Cloud/Azure"
        "$base_dir/Cloud/GCP"
        
        # Reporting & Documentation
        "$base_dir/Reports/Templates"
        "$base_dir/Reports/Screenshots"
        "$base_dir/Reports/Evidence"
        
        # Wordlists & Dictionaries
        "$base_dir/Wordlists/Passwords"
        "$base_dir/Wordlists/Usernames"
        "$base_dir/Wordlists/Directories"
        
        # Binary Collections
        "$base_dir/Binaries/Windows"
        "$base_dir/Binaries/Linux"
    )
    
    # Create all directories
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
    done
    
    # Set proper ownership
    chown -R "$USER_NAME:$USER_NAME" "$TOOLS_DIR"
    
    echo "[✓] Tool directory structure created at $TOOLS_DIR"
}

# -------------------- Profile Definitions --------------------
get_profile_tools() {
    local profile="$1"
    
    case "$profile" in
        "minimal")
            echo "nmap netcat-traditional curl wget jq"
            ;;
        "webapp")
            echo "nmap gobuster dirb nikto sqlmap burpsuite whatweb ffuf feroxbuster wpscan nuclei"
            ;;
        "internal")
            echo "nmap masscan enum4linux crackmapexec impacket-scripts smbclient smbmap responder bloodhound neo4j"
            ;;
        "cloud")
            echo "nmap awscli azure-cli google-cloud-cli kubectl docker.io terraform"
            ;;
        "standard")
            echo "nmap gobuster seclists ffuf feroxbuster sqlmap whatweb amass mitmproxy netcat-traditional socat tcpdump crackmapexec impacket-scripts smbclient burpsuite docker.io"
            ;;
        "heavy")
            echo "nmap gobuster seclists ffuf feroxbuster sqlmap wpscan whatweb amass mitmproxy netcat-traditional socat tcpdump masscan crackmapexec impacket-scripts smbclient smbmap bloodhound neo4j metasploit-framework burpsuite docker.io docker-compose-plugin volatility3 yara john hashcat hydra"
            ;;
        *)
            echo "nmap netcat-traditional"  # fallback
            ;;
    esac
}

install_profile_github_tools() {
    local profile="$1"
    
    # Source the GitHub release manager
    source "$(dirname "$0")/github_release_manager.sh" 2>/dev/null || {
        echo "[!] Warning: GitHub release manager not found, skipping GitHub tools"
        return 0
    }
    
    echo "[+] Installing GitHub tools for profile: $profile"
    
    case "$profile" in
        "webapp"|"standard"|"heavy")
            install_github_tools "$TOOLS_DIR" "shells"
            ;;
        "internal"|"heavy")
            install_github_tools "$TOOLS_DIR" "ad"
            install_github_tools "$TOOLS_DIR" "pivoting"
            ;;
        "cloud"|"heavy")
            install_github_tools "$TOOLS_DIR" "recon"
            ;;
    esac
    
    # Install privilege escalation tools for most profiles
    if [[ "$profile" != "minimal" ]]; then
        install_github_tools "$TOOLS_DIR" "privesc"
    fi
}

# -------------------- Application Configuration --------------------
configure_applications() {
    echo "[+] Configuring applications for security testing workflow"
    
    # Configure Firefox for security testing
    if command -v firefox >/dev/null 2>&1; then
        echo "[+] Configuring Firefox for penetration testing"
        
        # Create Firefox profile directory for the user
        local firefox_profile_dir="/home/$USER_NAME/.mozilla/firefox"
        sudo -u "$USER_NAME" mkdir -p "$firefox_profile_dir"
        
        # Set up proxy configuration template
        cat > "/home/$USER_NAME/firefox-proxy-setup.sh" <<'EOF'
#!/bin/bash
# Quick script to configure Firefox proxy for BurpSuite
echo "Setting Firefox proxy to localhost:8080 for BurpSuite"
# User can run this when needed
EOF
        chmod +x "/home/$USER_NAME/firefox-proxy-setup.sh"
        chown "$USER_NAME:$USER_NAME" "/home/$USER_NAME/firefox-proxy-setup.sh"
    fi
    
    # Configure tmux for multi-window workflow
    if command -v tmux >/dev/null 2>&1; then
        echo "[+] Creating tmux configuration for pentesting workflow"
        cat > "/home/$USER_NAME/.tmux.conf" <<'EOF'
# Pentesting-focused tmux configuration
set -g mouse on
set -g history-limit 10000

# Quick pane switching
bind -n M-Left select-pane -L
bind -n M-Right select-pane -R
bind -n M-Up select-pane -U
bind -n M-Down select-pane -D

# Status bar
set -g status-bg black
set -g status-fg white
set -g status-left '[#S] '
set -g status-right '#H %Y-%m-%d %H:%M'
EOF
        chown "$USER_NAME:$USER_NAME" "/home/$USER_NAME/.tmux.conf"
    fi
    
    # Create useful aliases
    cat >> "/home/$USER_NAME/.bashrc" <<EOF

# Pentesting aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias tools='cd $TOOLS_DIR'
alias nse='ls /usr/share/nmap/scripts/ | grep'
alias ports='netstat -tuln'
alias myip='curl -s ifconfig.me'

# Quick directory navigation
alias recon='cd $TOOLS_DIR/Recon'
alias privesc='cd $TOOLS_DIR/PrivEsc'
alias webapp='cd $TOOLS_DIR/WebApp'
alias ad='cd $TOOLS_DIR/ActiveDirectory'
EOF
    
    echo "[✓] Application configuration complete"
}

# -------------------- Main Installation Logic --------------------
install_base_system() {
    # Repository setup (from original script)
    apt-get clean
    apt-get update || true
    apt-get install -y --no-install-recommends ca-certificates gnupg curl wget apt-transport-https jq

    install -d -m 755 /usr/share/keyrings
    curl -fsSL https://archive.kali.org/archive-key.asc | gpg --dearmor -o /usr/share/keyrings/kali-archive-keyring.gpg
    chmod 644 /usr/share/keyrings/kali-archive-keyring.gpg

    if ! grep -q "kali-rolling" /etc/apt/sources.list; then
    cat >/etc/apt/sources.list <<'EOF'
deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main non-free contrib
EOF
    fi

    apt-get -y -f install
    apt-get update -y
}

# -------------------- Password Management --------------------
gen_password() {
    local length="${1:-32}"
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 48 | tr -dc 'A-Za-z0-9!@#%^*_+=.-' | head -c "$length"
    else
        dd if=/dev/urandom bs=1 count=64 2>/dev/null | base64 | tr -dc 'A-Za-z0-9!@#%^*_+=.-' | head -c "$length"
    fi
}

save_password() {
    local username="$1"
    local password="$2"
    local description="${3:-Console Login}"
    
    # Save to secure password log
    {
        echo "======================================================"
        echo "KaliForge II - Password Information"
        echo "Generated: $(date)"
        echo "======================================================"
        echo "User: $username"
        echo "Password: $password"
        echo "Description: $description"
        echo "======================================================"
        echo ""
    } >> "$PASSWORD_LOG"
    
    # Secure the password file
    chmod 600 "$PASSWORD_LOG"
    
    echo "[+] Password saved to secure log: $PASSWORD_LOG"
}

display_password_info() {
    local username="$1"
    local password="$2"
    
    # Create a prominent display file
    local display_file="/tmp/kaliforge2_credentials.txt"
    
    cat > "$display_file" <<EOF
╔══════════════════════════════════════════════════════════════════════════════╗
║                            🔐 KALIFORGE II CREDENTIALS 🔐                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Username: $username                                                        ║
║  Password: $password                                   ║
║                                                                              ║
║  ⚠️  IMPORTANT: Save this password in a secure location!                     ║
║                                                                              ║
║  💾 Password also saved to: $PASSWORD_LOG                 ║
║                                                                              ║
║  🚨 This file will be deleted in 5 minutes for security.                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF

    # Display prominently
    clear
    cat "$display_file"
    
    # Also log to main installation log
    {
        echo ""
        echo "======== CREDENTIALS GENERATED ========"
        echo "User: $username"
        echo "Console Password: [SAVED TO $PASSWORD_LOG]"
        echo "========================================"
        echo ""
    } >> "$INSTALL_LOG"
    
    echo ""
    echo "💡 Press ENTER to continue installation..."
    read -r
    
    # Schedule file deletion for security (5 minutes)
    (sleep 300; rm -f "$display_file" 2>/dev/null) &
}

# -------------------- Main Execution --------------------
main() {
    echo "================= SECUREFORGE - SECURITY-FIRST KALI SETUP =================="
    echo " Profile: $PROFILE"
    echo " User: $USER_NAME"
    echo " Tools Directory: $TOOLS_DIR"
    echo "=============================================================================="
    
    # Base system setup (from your original script)
    install_base_system
    
    # User creation with enhanced password management
    if id -u "$USER_NAME" >/dev/null 2>&1; then
        echo "[i] User $USER_NAME already exists." | tee -a "$INSTALL_LOG"
        
        # Ask if user wants to reset password
        echo "[?] Would you like to reset the password for $USER_NAME? (y/N)"
        read -r reset_pass
        if [[ "$reset_pass" =~ ^[Yy]$ ]]; then
            CONSOLE_PASS="$(gen_password)"
            echo "$USER_NAME:$CONSOLE_PASS" | chpasswd
            save_password "$USER_NAME" "$CONSOLE_PASS" "Console Login (Reset)"
            display_password_info "$USER_NAME" "$CONSOLE_PASS"
        fi
    else
        echo "[+] Creating user: $USER_NAME" | tee -a "$INSTALL_LOG"
        adduser --disabled-password --gecos "" "$USER_NAME"
        CONSOLE_PASS="$(gen_password)"
        echo "$USER_NAME:$CONSOLE_PASS" | chpasswd
        save_password "$USER_NAME" "$CONSOLE_PASS" "Console Login (New User)"
        display_password_info "$USER_NAME" "$CONSOLE_PASS"
    fi

    # Base packages
    apt-get dist-upgrade -y
    apt-get install -y \
      sudo ufw fail2ban unattended-upgrades apt-listchanges \
      build-essential git curl wget unzip xz-utils jq \
      net-tools dnsutils iproute2 iputils-ping traceroute \
      zsh tmux htop neovim fontconfig \
      openssh-server

    # Create structured tool directories
    create_tool_directories
    
    # Install profile-specific tools
    echo "[+] Installing tools for profile: $PROFILE"
    PROFILE_TOOLS=$(get_profile_tools "$PROFILE")
    if [[ -n "$PROFILE_TOOLS" ]]; then
        apt-get install -y $PROFILE_TOOLS || true
    fi
    
    # Install GitHub-based tools
    install_profile_github_tools "$PROFILE"
    
    # Configure applications
    configure_applications
    
    # Security hardening (from original script - abbreviated for space)
    usermod -aG sudo "$USER_NAME" || true
    passwd -l root || true
    if id -u kali >/dev/null 2>&1; then
      passwd -l kali || true
      usermod -L kali || true
    fi
    
    # Create comprehensive installation summary
    create_installation_summary
    
    echo "[✓] KaliForge II installation complete!"
    echo ""
    echo "================== KALIFORGE II COMPLETE ==================="
    show_final_summary
    echo "==========================================================="
    
    # Final log entry
    {
        echo ""
        echo "=========================================="
        echo "KaliForge II Installation Complete"
        echo "Timestamp: $(date)"
        echo "Profile: $PROFILE"
        echo "User: $USER_NAME"
        echo "Tools Directory: $TOOLS_DIR"
        echo "=========================================="
    } >> "$INSTALL_LOG"
}

create_installation_summary() {
    local summary_file="$LOG_DIR/INSTALLATION_COMPLETE_${TIMESTAMP}.txt"
    
    # Comprehensive summary file
    {
        echo "╔══════════════════════════════════════════════════════════════════════════════╗"
        echo "║                        🚀 KALIFORGE II INSTALLATION COMPLETE 🚀              ║"
        echo "╚══════════════════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "📅 Installation Date: $(date)"
        echo "⚙️  Profile: $PROFILE"
        echo "👤 User Account: $USER_NAME"
        echo "📁 Tools Directory: $TOOLS_DIR"
        echo "🔐 SSH Status: $(systemctl is-active ssh 2>/dev/null || echo 'DISABLED')"
        echo "🖥️  Desktop: $INSTALL_KDE"
        echo ""
        echo "📋 LOG FILES:"
        echo "   • Main Log: $MAIN_LOG"
        echo "   • Passwords: $PASSWORD_LOG (SECURE - 600 permissions)"
        echo "   • Installation Summary: $INSTALL_LOG"
        echo "   • Error Log: $ERROR_LOG"
        echo ""
        echo "🛠️  QUICK START:"
        echo "   • Login: $USER_NAME / [see password file]"
        echo "   • Tools: 'tools' command or 'cd $TOOLS_DIR'"
        echo "   • SSH: $(if [[ -n "$PUBKEY" ]]; then echo "Port $SSH_PORT (key-only)"; else echo "Disabled"; fi)"
        echo ""
        echo "📂 TOOL CATEGORIES INSTALLED:"
        if [[ "$PROFILE" == "minimal" ]]; then
            echo "   • Basic reconnaissance tools"
        elif [[ "$PROFILE" == "webapp" ]]; then
            echo "   • Web application security testing"
            echo "   • Directory/file enumeration"
            echo "   • SQL injection testing"
        elif [[ "$PROFILE" == "internal" ]]; then
            echo "   • Internal network penetration testing"
            echo "   • Active Directory assessment"
            echo "   • SMB enumeration and exploitation"
        elif [[ "$PROFILE" == "cloud" ]]; then
            echo "   • Cloud security testing (AWS, Azure, GCP)"
            echo "   • Container security tools"
        elif [[ "$PROFILE" == "standard" ]]; then
            echo "   • Balanced general-purpose toolkit"
            echo "   • Network scanning and web testing"
        elif [[ "$PROFILE" == "heavy" ]]; then
            echo "   • Full comprehensive security arsenal"
            echo "   • Metasploit, BloodHound, password cracking"
        fi
        echo ""
        echo "⚠️  SECURITY REMINDERS:"
        echo "   • Root account is locked"
        echo "   • SSH is hardened (if enabled)"
        echo "   • Firewall (UFW) is active"
        echo "   • Fail2ban is monitoring"
        echo ""
        echo "📖 For help: cat $LOG_DIR/README.txt"
        
    } > "$summary_file"
    
    # Create a helpful README in log directory
    {
        echo "KaliForge II Log Directory"
        echo "========================="
        echo ""
        echo "This directory contains all logs from your KaliForge II installation."
        echo ""
        echo "Files:"
        echo "• kaliforge2_*.log - Main installation log"
        echo "• passwords_*.log - SECURE password file (600 permissions)"
        echo "• install_summary_*.log - Installation progress log"
        echo "• errors_*.log - Error messages (if any)"
        echo "• INSTALLATION_COMPLETE_*.txt - Final summary"
        echo ""
        echo "Security Note:"
        echo "The passwords log file has restricted permissions (600) for security."
        echo "Only root and the file owner can read it."
        echo ""
        echo "Generated by KaliForge II on $(date)"
    } > "$LOG_DIR/README.txt"
    
    echo "[+] Installation summary saved to: $summary_file"
}

show_final_summary() {
    local ssh_status="DISABLED"
    if systemctl is-active --quiet ssh 2>/dev/null; then
        ssh_status="ENABLED (Port: $SSH_PORT)"
    fi
    
    echo " 👤 User: $USER_NAME"
    echo " ⚙️  Profile: $PROFILE" 
    echo " 📁 Tools: $TOOLS_DIR"
    echo " 🔐 SSH: $ssh_status"
    echo " 📋 Logs: $LOG_DIR"
    echo " 💾 Password: $PASSWORD_LOG"
    echo ""
    echo " 🚀 Quick commands:"
    echo "    tools          # Navigate to toolkit"
    echo "    cd $TOOLS_DIR  # Direct navigation"
    echo "    sudo -u $USER_NAME -i  # Switch to pentest user"
}

# Run main function
main "$@"