#!/usr/bin/env bash
# KaliForge II TUI - Next-generation interactive configuration interface
# Provides user-friendly selection of profiles and comprehensive logging options

set -euo pipefail

# Check for required dependencies
check_dependencies() {
    local missing_deps=()
    
    if ! command -v dialog >/dev/null 2>&1; then
        missing_deps+=("dialog")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo "Missing required dependencies: ${missing_deps[*]}"
        echo "Installing dependencies..."
        apt-get update && apt-get install -y "${missing_deps[@]}"
    fi
}

# Configuration variables
USER_NAME="${USER_NAME:-tikket}"
SSH_PORT="${SSH_PORT:-2222}"
PROFILE="${PROFILE:-standard}"
INSTALL_KDE="${INSTALL_KDE:-true}"
PUBKEY="${PUBKEY:-}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

# TUI Functions
show_welcome() {
    dialog --title "KaliForge II Setup" --msgbox "🚀 Welcome to KaliForge II! 🚀\n\nNext-generation security-first Kali Linux environment setup with:\n\n• Enhanced password management\n• Comprehensive logging system  \n• Structured tool organization\n• Workflow-specific profiles\n• GitHub release integration\n\nPress OK to continue..." 14 70
}

select_profile() {
    local choice
    choice=$(dialog --title "Profile Selection" \
        --menu "Choose your KaliForge II profile:" 20 80 10 \
        "minimal" "Basic tools only (nmap, netcat, curl)" \
        "webapp" "Web application testing focused" \
        "internal" "Internal network penetration testing" \
        "cloud" "Cloud security testing tools" \
        "standard" "Balanced toolkit for general pentesting" \
        "heavy" "Full arsenal including Metasploit & BloodHound" \
        3>&1 1>&2 2>&3 3>&-)
    
    if [[ -n "$choice" ]]; then
        PROFILE="$choice"
    fi
}

configure_user() {
    local input
    input=$(dialog --title "User Configuration" \
        --inputbox "Enter username for the pentesting user:" 10 60 "$USER_NAME" \
        3>&1 1>&2 2>&3 3>&-)
    
    if [[ -n "$input" ]]; then
        USER_NAME="$input"
    fi
}

configure_ssh() {
    local configure_ssh_choice
    configure_ssh_choice=$(dialog --title "SSH Configuration" \
        --yesno "Do you want to configure SSH access?\n\n(Requires SSH public key)" 10 60 \
        3>&1 1>&2 2>&3 3>&-)
    
    if [[ $? -eq 0 ]]; then
        # Get SSH port
        local port_input
        port_input=$(dialog --title "SSH Port" \
            --inputbox "Enter SSH port (default: 2222):" 10 60 "$SSH_PORT" \
            3>&1 1>&2 2>&3 3>&-)
        
        if [[ -n "$port_input" ]]; then
            SSH_PORT="$port_input"
        fi
        
        # Get public key
        local pubkey_input
        pubkey_input=$(dialog --title "SSH Public Key" \
            --inputbox "Enter your SSH public key:" 10 80 "$PUBKEY" \
            3>&1 1>&2 2>&3 3>&-)
        
        if [[ -n "$pubkey_input" ]]; then
            PUBKEY="$pubkey_input"
        fi
    fi
}

configure_desktop() {
    local install_desktop
    install_desktop=$(dialog --title "Desktop Environment" \
        --yesno "Install KDE desktop environment?\n\n(Recommended for GUI-based tools)" 10 60 \
        3>&1 1>&2 2>&3 3>&-)
    
    if [[ $? -eq 0 ]]; then
        INSTALL_KDE="true"
    else
        INSTALL_KDE="false"
    fi
}

configure_github() {
    local use_github
    use_github=$(dialog --title "GitHub Integration" \
        --yesno "Do you have a GitHub token for enhanced tool downloads?\n\n(Optional but recommended for latest releases)" 10 70 \
        3>&1 1>&2 2>&3 3>&-)
    
    if [[ $? -eq 0 ]]; then
        local token_input
        token_input=$(dialog --title "GitHub Token" \
            --passwordbox "Enter your GitHub personal access token:" 10 60 \
            3>&1 1>&2 2>&3 3>&-)
        
        if [[ -n "$token_input" ]]; then
            GITHUB_TOKEN="$token_input"
        fi
    fi
}

show_configuration_summary() {
    local ssh_status="DISABLED"
    if [[ -n "$PUBKEY" ]]; then
        ssh_status="ENABLED (Port: $SSH_PORT)"
    fi
    
    local github_status="Not configured"
    if [[ -n "$GITHUB_TOKEN" ]]; then
        github_status="Configured"
    fi
    
    dialog --title "Configuration Summary" \
        --yesno "Please review your configuration:\n\nProfile: $PROFILE\nUser: $USER_NAME\nKDE Desktop: $INSTALL_KDE\nSSH: $ssh_status\nGitHub Integration: $github_status\n\nProceed with installation?" 15 70
}

show_profile_details() {
    case "$PROFILE" in
        "minimal")
            dialog --title "Minimal Profile" --msgbox "Basic reconnaissance and connectivity tools:\n• nmap\n• netcat\n• curl, wget\n• jq\n\nIdeal for: Basic network testing, lightweight VMs" 12 60
            ;;
        "webapp")
            dialog --title "Web Application Profile" --msgbox "Web application security testing:\n• gobuster, dirb, feroxbuster\n• sqlmap, nuclei\n• BurpSuite, OWASP ZAP\n• whatweb, wpscan\n\nIdeal for: Web app penetration testing" 14 60
            ;;
        "internal")
            dialog --title "Internal Network Profile" --msgbox "Internal network penetration testing:\n• crackmapexec, impacket\n• enum4linux, smbclient\n• responder, BloodHound\n• Active Directory tools\n\nIdeal for: Internal network assessments" 14 60
            ;;
        "cloud")
            dialog --title "Cloud Security Profile" --msgbox "Cloud security testing tools:\n• AWS CLI, Azure CLI, GCP CLI\n• kubectl, terraform\n• Cloud-specific scanners\n• Container security tools\n\nIdeal for: Cloud penetration testing" 14 60
            ;;
        "standard")
            dialog --title "Standard Profile" --msgbox "Balanced toolkit for general pentesting:\n• Network scanning (nmap, masscan)\n• Web testing (gobuster, sqlmap)\n• Basic exploitation tools\n• Docker support\n\nIdeal for: General penetration testing" 14 60
            ;;
        "heavy")
            dialog --title "Heavy Profile" --msgbox "Full arsenal of security tools:\n• Everything from standard profile\n• Metasploit Framework\n• BloodHound + Neo4j\n• Password cracking (john, hashcat)\n• Forensics tools\n\nIdeal for: Comprehensive security assessments" 16 70
            ;;
    esac
}

create_config_file() {
    cat > "/tmp/secureforge.conf" <<EOF
# SecureForge Configuration
export USER_NAME="$USER_NAME"
export SSH_PORT="$SSH_PORT"
export PROFILE="$PROFILE"
export INSTALL_KDE="$INSTALL_KDE"
export PUBKEY="$PUBKEY"
export GITHUB_TOKEN="$GITHUB_TOKEN"
EOF
    echo "[+] Configuration saved to /tmp/secureforge.conf"
}

run_installation() {
    # Source configuration
    source "/tmp/secureforge.conf"
    
    # Show progress dialog
    (
        echo "10" ; echo "# Setting up base system..."
        sleep 2
        echo "30" ; echo "# Installing profile tools..."
        sleep 3
        echo "60" ; echo "# Configuring security settings..."
        sleep 2
        echo "80" ; echo "# Setting up tool directories..."
        sleep 2
        echo "100" ; echo "# Installation complete!"
    ) | dialog --title "Installing SecureForge" --gauge "Starting installation..." 10 70 0
    
    # Run the actual installation
    clear
    echo "Starting SecureForge installation..."
    echo "Configuration loaded from /tmp/secureforge.conf"
    
    # Check if kaliforge2.sh exists
    local script_dir="$(dirname "$0")"
    if [[ -f "$script_dir/kaliforge2.sh" ]]; then
        echo "Running KaliForge II installation..."
        bash "$script_dir/kaliforge2.sh"
    else
        echo "Error: kaliforge2.sh not found in $script_dir"
        echo "Please ensure both scripts are in the same directory."
        exit 1
    fi
}

# Main TUI flow
main() {
    # Ensure running as root
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi
    
    # Check dependencies
    check_dependencies
    
    # Main TUI flow
    show_welcome
    
    while true; do
        select_profile
        show_profile_details
        
        local continue_choice
        continue_choice=$(dialog --title "Profile Selected" \
            --menu "Profile: $PROFILE\nWhat would you like to do next?" 15 60 5 \
            "configure" "Continue with configuration" \
            "change" "Select different profile" \
            "details" "View profile details again" \
            "quit" "Exit setup" \
            3>&1 1>&2 2>&3 3>&-)
        
        case "$continue_choice" in
            "configure")
                break
                ;;
            "change")
                continue
                ;;
            "details")
                show_profile_details
                ;;
            "quit"|"")
                clear
                echo "SecureForge setup cancelled."
                exit 0
                ;;
        esac
    done
    
    # Configuration steps
    configure_user
    configure_ssh
    configure_desktop
    configure_github
    
    # Show summary and confirm
    if show_configuration_summary; then
        create_config_file
        
        # Final confirmation
        local final_choice
        final_choice=$(dialog --title "Ready to Install" \
            --menu "Choose installation option:" 12 60 3 \
            "install" "Start installation now" \
            "save" "Save configuration and exit" \
            "cancel" "Cancel setup" \
            3>&1 1>&2 2>&3 3>&-)
        
        case "$final_choice" in
            "install")
                run_installation
                ;;
            "save")
                clear
                echo "Configuration saved to /tmp/secureforge.conf"
                echo "Run 'source /tmp/secureforge.conf && bash secureforge.sh' to install later."
                ;;
            "cancel"|"")
                clear
                echo "SecureForge setup cancelled."
                ;;
        esac
    else
        clear
        echo "SecureForge setup cancelled."
    fi
    
    clear
}

# Cleanup function
cleanup() {
    clear
    echo "SecureForge TUI exited."
}

trap cleanup EXIT
main "$@"