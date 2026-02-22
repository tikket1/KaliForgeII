#!/usr/bin/env bash
# KaliForge II - Consolidated security-first Kali Linux environment setup
# Merges: kali_bootstrapper.sh + kaliforge2.sh + github_release_manager_parallel.sh
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive

# -------------------- Simple Logging --------------------
LOG="/var/log/kaliforge2.log"
mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1
set -x
trap 'echo "ERROR at line $LINENO: $BASH_COMMAND"; exit 1' ERR

# -------------------- Configuration (env-var driven) --------------------
USER_NAME="${USER_NAME:-tikket}"
SSH_PORT="${SSH_PORT:-2222}"
PROFILE="${PROFILE:-standard}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
PUBKEY="${PUBKEY:-}"
INSTALL_KDE="${INSTALL_KDE:-true}"
ALLOWLIST_CIDR="${ALLOWLIST_CIDR:-}"
DISABLE_IPV6="${DISABLE_IPV6:-false}"
MAX_PARALLEL_DOWNLOADS="${MAX_PARALLEL_DOWNLOADS:-4}"
TOOLS_DIR="/home/$USER_NAME/PentestTools"

# -------------------- Helpers --------------------
gen_password() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 48 | tr -dc 'A-Za-z0-9!@#%^*_+=_' | head -c 28
    else
        dd if=/dev/urandom bs=1 count=64 2>/dev/null | base64 | tr -dc 'A-Za-z0-9!@#%^*_+=_' | head -c 28
    fi
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
            echo "nmap netcat-traditional"
            ;;
    esac
}

# -------------------- Tool Directory Structure --------------------
create_tool_directories() {
    echo "[+] Creating structured tool directories"
    local base_dir="$TOOLS_DIR"
    local directories=(
        "$base_dir/Recon/DNS"
        "$base_dir/Recon/Web"
        "$base_dir/Recon/Network"
        "$base_dir/Recon/OSINT"
        "$base_dir/Recon/Subdomain"
        "$base_dir/WebApp/Scanners"
        "$base_dir/WebApp/Proxies"
        "$base_dir/WebApp/Fuzzing"
        "$base_dir/WebApp/SQLi"
        "$base_dir/WebApp/XSS"
        "$base_dir/Network/Scanning"
        "$base_dir/Network/Exploitation"
        "$base_dir/Network/MITM"
        "$base_dir/Network/Wireless"
        "$base_dir/PrivEsc/Linux"
        "$base_dir/PrivEsc/Windows"
        "$base_dir/PrivEsc/Windows/PrintSpoofer"
        "$base_dir/PrivEsc/Windows/GodPotato"
        "$base_dir/PostExploit/Persistence"
        "$base_dir/PostExploit/Lateral"
        "$base_dir/PostExploit/Exfiltration"
        "$base_dir/ActiveDirectory/Enumeration"
        "$base_dir/ActiveDirectory/BloodHound"
        "$base_dir/ActiveDirectory/Kerberos"
        "$base_dir/ActiveDirectory/SharpHound"
        "$base_dir/Pivoting/Linux"
        "$base_dir/Pivoting/Windows"
        "$base_dir/Shells/Reverse"
        "$base_dir/Shells/WebShells"
        "$base_dir/Shells/Generators"
        "$base_dir/C2/Cobalt"
        "$base_dir/C2/Empire"
        "$base_dir/C2/Sliver"
        "$base_dir/Cloud/AWS"
        "$base_dir/Cloud/Azure"
        "$base_dir/Cloud/GCP"
        "$base_dir/Reports/Templates"
        "$base_dir/Reports/Screenshots"
        "$base_dir/Reports/Evidence"
        "$base_dir/Wordlists/Passwords"
        "$base_dir/Wordlists/Usernames"
        "$base_dir/Wordlists/Directories"
        "$base_dir/Binaries/Windows"
        "$base_dir/Binaries/Linux"
    )
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
    done
    chown -R "$USER_NAME:$USER_NAME" "$TOOLS_DIR"
    echo "[+] Tool directory structure created at $TOOLS_DIR"
}

# -------------------- GitHub Release Downloads --------------------
download_github_release() {
    local repo="$1"
    local pattern="$2"
    local dest_dir="$3"
    local filename="${4:-}"
    local github_token="${GITHUB_TOKEN:-}"
    local attempt=1
    local max_attempts=3

    echo "[+] Downloading latest release from $repo matching '$pattern'"

    local api_url="https://api.github.com/repos/$repo/releases/latest"
    local curl_headers=()
    if [[ -n "$github_token" ]]; then
        curl_headers+=("-H" "Authorization: Bearer $github_token")
    fi

    while [[ $attempt -le $max_attempts ]]; do
        # Fetch release info
        local release_data
        if ! release_data=$(timeout 30 curl -s "${curl_headers[@]}" "$api_url" 2>/dev/null); then
            echo "[!] Failed to fetch release data for $repo (attempt $attempt)" >&2
            ((attempt++)); sleep $((attempt * 2)); continue
        fi

        # Extract download URL via jq
        local download_url
        download_url=$(echo "$release_data" | jq -r --arg pattern "$pattern" \
            '.assets[] | select(.name | test($pattern; "i")) | .browser_download_url' | head -n1)

        if [[ -z "$download_url" || "$download_url" == "null" ]]; then
            echo "[!] No matching asset for '$pattern' in $repo" >&2
            return 1
        fi

        local asset_name
        asset_name=$(basename "$download_url")
        local final_filename="${filename:-$asset_name}"
        local full_path="$dest_dir/$final_filename"
        mkdir -p "$dest_dir"

        echo "[+] Downloading $asset_name -> $full_path (attempt $attempt)"
        if timeout 300 curl -L --retry 2 --retry-delay 2 --connect-timeout 30 \
            -o "$full_path" "$download_url" 2>/dev/null; then

            # Extract compressed files
            case "$asset_name" in
                *.tar.gz|*.tgz)
                    tar -xzf "$full_path" -C "$dest_dir" 2>/dev/null && rm -f "$full_path" || true
                    ;;
                *.gz)
                    gunzip "$full_path" 2>/dev/null || true
                    ;;
                *.zip)
                    command -v unzip >/dev/null && unzip -qo "$full_path" -d "$dest_dir" 2>/dev/null && rm -f "$full_path" || true
                    ;;
            esac

            # Make binaries executable
            local final_file="$dest_dir/$final_filename"
            [[ "$asset_name" =~ \.gz$ ]] && final_file="$dest_dir/${final_filename%.gz}"
            if [[ -f "$final_file" ]] && file "$final_file" 2>/dev/null | grep -q "executable"; then
                chmod +x "$final_file"
            fi

            echo "[+] Successfully installed: $final_filename"
            return 0
        fi

        echo "[!] Download failed (attempt $attempt)" >&2
        ((attempt++)); sleep $((attempt * 2))
    done
    return 1
}

# -------------------- Parallel Download Engine --------------------
download_tools_parallel() {
    local category="$1"
    local tools_dir="$2"
    local -a jobs=()

    case "$category" in
        "pivoting")
            jobs=(
                "jpillora/chisel|linux_amd64\.gz$|$tools_dir/Pivoting/Linux|chisel_x64"
                "jpillora/chisel|linux_386\.gz$|$tools_dir/Pivoting/Linux|chisel_x86"
                "jpillora/chisel|windows_amd64\.gz$|$tools_dir/Pivoting/Windows|chisel_x64.exe"
                "jpillora/chisel|windows_386\.gz$|$tools_dir/Pivoting/Windows|chisel_x86.exe"
            )
            ;;
        "privesc")
            jobs=(
                "carlospolop/PEASS-ng|linpeas\.sh$|$tools_dir/PrivEsc/Linux|linpeas.sh"
                "carlospolop/PEASS-ng|winPEASx64\.exe$|$tools_dir/PrivEsc/Windows|winPEASx64.exe"
                "carlospolop/PEASS-ng|winPEASx86\.exe$|$tools_dir/PrivEsc/Windows|winPEASx86.exe"
                "DominicBreuker/pspy|pspy64$|$tools_dir/PrivEsc/Linux|pspy64"
                "DominicBreuker/pspy|pspy32$|$tools_dir/PrivEsc/Linux|pspy32"
                "itm4n/PrintSpoofer|PrintSpoofer64\.exe$|$tools_dir/PrivEsc/Windows/PrintSpoofer|PrintSpoofer64.exe"
                "itm4n/PrintSpoofer|PrintSpoofer32\.exe$|$tools_dir/PrivEsc/Windows/PrintSpoofer|PrintSpoofer32.exe"
                "BeichenDream/GodPotato|GodPotato-NET4\.exe$|$tools_dir/PrivEsc/Windows/GodPotato|GodPotato-NET4.exe"
            )
            ;;
        "ad")
            jobs=(
                "BloodHoundAD/SharpHound|SharpHound.*\.exe$|$tools_dir/ActiveDirectory/SharpHound|SharpHound.exe"
                "BloodHoundAD/BloodHound|BloodHound-linux-x64.*\.zip$|$tools_dir/ActiveDirectory|BloodHound.zip"
            )
            ;;
        "c2")
            jobs=(
                "BishopFox/sliver|sliver-server_linux$|$tools_dir/C2/Sliver|sliver-server"
                "BishopFox/sliver|sliver-client_linux$|$tools_dir/C2/Sliver|sliver-client"
                "BishopFox/sliver|sliver-server_windows\.exe$|$tools_dir/C2/Sliver|sliver-server.exe"
                "BishopFox/sliver|sliver-client_windows\.exe$|$tools_dir/C2/Sliver|sliver-client.exe"
            )
            ;;
    esac

    if [[ ${#jobs[@]} -eq 0 ]]; then
        return 0
    fi

    echo "[+] Queuing ${#jobs[@]} parallel downloads for: $category"
    local -a pids=()

    for job in "${jobs[@]}"; do
        IFS='|' read -r repo pattern dest filename <<< "$job"

        # Limit concurrency
        if [[ ${#pids[@]} -ge $MAX_PARALLEL_DOWNLOADS ]]; then
            wait "${pids[0]}" 2>/dev/null || true
            pids=("${pids[@]:1}")
        fi

        (download_github_release "$repo" "$pattern" "$dest" "$filename") &
        pids+=($!)
        sleep 0.2
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    echo "[+] Parallel downloads complete for: $category"
}

clone_repositories_parallel() {
    local category="$1"
    local tools_dir="$2"
    local -a jobs=()

    case "$category" in
        "recon")
            jobs=("https://github.com/techgaun/github-dorks|$tools_dir/Recon/github-dorks")
            ;;
        "ad")
            jobs=(
                "https://github.com/dirkjanm/PKINITtools|$tools_dir/ActiveDirectory/PKINITtools"
                "https://github.com/Greenwolf/ntlm_theft|$tools_dir/ActiveDirectory/ntlm_theft"
            )
            ;;
        "shells")
            jobs=(
                "https://github.com/brightio/penelope|$tools_dir/Shells/penelope"
                "https://github.com/samratashok/nishang|$tools_dir/Shells/nishang"
                "https://github.com/t3l3machus/hoaxshell|$tools_dir/Shells/hoaxshell"
            )
            ;;
    esac

    [[ ${#jobs[@]} -eq 0 ]] && return 0

    echo "[+] Cloning ${#jobs[@]} repositories for: $category"
    local -a pids=()

    for job in "${jobs[@]}"; do
        IFS='|' read -r repo_url dest_path <<< "$job"
        (
            echo "[+] Cloning $(basename "$repo_url")"
            git clone --depth 1 "$repo_url" "$dest_path" 2>/dev/null || echo "[!] Failed to clone $repo_url" >&2
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    echo "[+] Repository cloning complete"
}

install_github_tools_parallel() {
    local tools_dir="$1"
    local category="$2"

    echo "[+] Installing GitHub tools: $category"
    case "$category" in
        "pivoting"|"privesc"|"ad"|"c2")
            download_tools_parallel "$category" "$tools_dir"
            ;;
        "recon"|"shells")
            clone_repositories_parallel "$category" "$tools_dir"
            ;;
        *)
            echo "[!] Unknown category: $category"
            return 1
            ;;
    esac
}

# -------------------- Profile GitHub Tool Installation --------------------
install_profile_github_tools() {
    local profile="$1"

    echo "[+] Installing GitHub tools for profile: $profile (parallel mode)"

    case "$profile" in
        "webapp"|"standard"|"heavy")
            install_github_tools_parallel "$TOOLS_DIR" "shells" &
            ;;
    esac

    case "$profile" in
        "internal"|"heavy")
            install_github_tools_parallel "$TOOLS_DIR" "ad" &
            install_github_tools_parallel "$TOOLS_DIR" "pivoting" &
            ;;
    esac

    case "$profile" in
        "cloud"|"heavy")
            install_github_tools_parallel "$TOOLS_DIR" "recon" &
            ;;
    esac

    if [[ "$profile" == "heavy" ]]; then
        install_github_tools_parallel "$TOOLS_DIR" "c2" &
    fi

    if [[ "$profile" != "minimal" ]]; then
        install_github_tools_parallel "$TOOLS_DIR" "privesc" &
    fi

    echo "[+] Waiting for parallel GitHub tool installations..."
    wait
    echo "[+] GitHub tool installation complete"
}

# -------------------- Base System Setup --------------------
install_base_system() {
    echo "[+] Setting up base system"

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
    apt-get dist-upgrade -y

    apt-get install -y \
        sudo ufw fail2ban unattended-upgrades apt-listchanges \
        build-essential git curl wget unzip xz-utils jq \
        net-tools dnsutils iproute2 iputils-ping traceroute \
        zsh tmux htop neovim fontconfig \
        open-vm-tools open-vm-tools-desktop \
        openssh-server

    systemctl enable --now open-vm-tools.service || true
}

# -------------------- User Creation --------------------
create_user() {
    if id -u "$USER_NAME" >/dev/null 2>&1; then
        echo "[+] User $USER_NAME already exists"
    else
        echo "[+] Creating user: $USER_NAME"
        adduser --disabled-password --gecos "" "$USER_NAME"
        CONSOLE_PASS="$(gen_password)"
        echo "$USER_NAME:$CONSOLE_PASS" | chpasswd
        echo "[+] Generated password for $USER_NAME: $CONSOLE_PASS"
        echo "[!] Save this password -- it will not be shown again"
    fi
}

# -------------------- Application Configuration --------------------
configure_applications() {
    echo "[+] Configuring applications"

    # tmux config
    if command -v tmux >/dev/null 2>&1; then
        cat > "/home/$USER_NAME/.tmux.conf" <<'EOF'
set -g mouse on
set -g history-limit 10000
bind -n M-Left select-pane -L
bind -n M-Right select-pane -R
bind -n M-Up select-pane -U
bind -n M-Down select-pane -D
set -g status-bg black
set -g status-fg white
set -g status-left '[#S] '
set -g status-right '#H %Y-%m-%d %H:%M'
EOF
        chown "$USER_NAME:$USER_NAME" "/home/$USER_NAME/.tmux.conf"
    fi

    # Shell aliases
    cat >> "/home/$USER_NAME/.bashrc" <<EOF

# Pentesting aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias tools='cd $TOOLS_DIR'
alias nse='ls /usr/share/nmap/scripts/ | grep'
alias ports='netstat -tuln'
alias myip='curl -s ifconfig.me'
alias recon='cd $TOOLS_DIR/Recon'
alias privesc='cd $TOOLS_DIR/PrivEsc'
alias webapp='cd $TOOLS_DIR/WebApp'
alias ad='cd $TOOLS_DIR/ActiveDirectory'
EOF
}

# -------------------- Security Hardening --------------------
harden_system() {
    echo "[+] Applying security hardening"

    # -- Unattended upgrades --
    dpkg-reconfigure -f noninteractive unattended-upgrades
    cat >/etc/apt/apt.conf.d/51unattended-upgrades-kali <<'EOF'
Unattended-Upgrade::Origins-Pattern { "o=Kali,a=kali-rolling"; };
Unattended-Upgrade::Automatic-Reboot "false";
EOF
    systemctl enable --now unattended-upgrades.service

    # -- Optional KDE desktop --
    if [[ "$INSTALL_KDE" == "true" ]]; then
        if ! dpkg -l | grep -q kali-desktop-kde; then
            apt-get install -y kali-desktop-kde sddm
            debconf-set-selections <<< "sddm shared/default-x-display-manager select sddm"
            dpkg-reconfigure -f noninteractive sddm || true
        fi
    fi

    # -- Wireshark setuid --
    echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
    apt-get install -y wireshark
    usermod -aG wireshark "$USER_NAME" || true
    if command -v dumpcap >/dev/null 2>&1; then
        chgrp wireshark "$(command -v dumpcap)"
        chmod 750 "$(command -v dumpcap)"
        setcap cap_net_raw,cap_net_admin+eip "$(command -v dumpcap)" || true
    fi

    # -- Docker --
    systemctl enable --now docker || true
    usermod -aG docker "$USER_NAME" || true

    # -- Root & kali lockdown --
    passwd -l root || true
    if id -u kali >/dev/null 2>&1; then
        passwd -l kali || true
        usermod -L kali || true
    fi

    # -- Sudo hardening --
    usermod -aG sudo "$USER_NAME" || true
    cat >/etc/sudoers.d/90-secure-sudo <<'EOF'
Defaults env_reset,timestamp_timeout=5,log_input,log_output
Defaults passwd_tries=3,badpass_message="sudo: authentication failed"
EOF
    chmod 440 /etc/sudoers.d/90-secure-sudo

    # -- SSH hardening (only if PUBKEY provided) --
    if [[ -n "$PUBKEY" ]]; then
        systemctl enable --now ssh
        install -d -m 700 -o "$USER_NAME" -g "$USER_NAME" "/home/$USER_NAME/.ssh"
        AUTH_KEYS="/home/$USER_NAME/.ssh/authorized_keys"
        touch "$AUTH_KEYS"; chown "$USER_NAME:$USER_NAME" "$AUTH_KEYS"; chmod 600 "$AUTH_KEYS"
        grep -qxF "$PUBKEY" "$AUTH_KEYS" || echo "$PUBKEY" >> "$AUTH_KEYS"

        SSHD=/etc/ssh/sshd_config
        cp -a "$SSHD" "${SSHD}.bak.$(date +%s)"
        sed -i -E 's/^#?Port .*/Port REPLACEME_PORT/' "$SSHD"
        sed -i -E 's/^#?PermitRootLogin.*/PermitRootLogin no/' "$SSHD"
        sed -i -E 's/^#?PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD"
        sed -i -E 's/^#?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$SSHD"
        sed -i -E 's/^#?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' "$SSHD"
        sed -i -E 's/^#?UsePAM.*/UsePAM no/' "$SSHD"
        grep -q '^PubkeyAuthentication' "$SSHD" || echo 'PubkeyAuthentication yes' >> "$SSHD"
        grep -q '^AllowUsers' "$SSHD" || echo "AllowUsers $USER_NAME" >> "$SSHD"
        sed -i "s/REPLACEME_PORT/$SSH_PORT/" "$SSHD"
        systemctl restart ssh
    else
        systemctl disable --now ssh || true
    fi

    # -- UFW firewall --
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 68/udp comment "DHCP client"
    ufw allow 53/tcp comment "DNS"
    ufw allow 53/udp comment "DNS"
    ufw allow 123/udp comment "NTP"
    ufw allow 224.0.0.251/udp comment "mDNS"

    if systemctl is-active --quiet ssh; then
        if [[ -n "$ALLOWLIST_CIDR" ]]; then
            IFS=',' read -r -a CIDRS <<<"$ALLOWLIST_CIDR"
            for c in "${CIDRS[@]}"; do
                ufw allow from "$c" to any port "$SSH_PORT" proto tcp comment "SSH allowlist"
            done
        else
            ufw limit "${SSH_PORT}"/tcp comment "SSH (rate-limited, key-only)"
        fi
    fi

    yes | ufw enable
    ufw status verbose || true

    # -- Fail2ban --
    cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 2h
findtime = 15m
maxretry = 5
backend = systemd

[sshd]
enabled = $(systemctl is-active --quiet ssh && echo true || echo false)
port = ${SSH_PORT}
logpath = %(sshd_log)s
maxretry = 5
EOF
    systemctl enable --now fail2ban || true

    # -- Sysctl hardening --
    cat >/etc/sysctl.d/99-kali-vm-hardening.conf <<'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1
EOF
    if [[ "$DISABLE_IPV6" == "true" ]]; then
        cat >>/etc/sysctl.d/99-kali-vm-hardening.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
    fi
    sysctl --system || true

    # -- Service hygiene --
    systemctl disable --now avahi-daemon || true
    systemctl disable --now cups || true
    systemctl disable --now rpcbind || true
    systemctl disable --now neo4j || true

    echo "[+] Security hardening complete"
}

# -------------------- Main --------------------
main() {
    echo "=================== KALIFORGE II ==================="
    echo " Profile:  $PROFILE"
    echo " User:     $USER_NAME"
    echo " Tools:    $TOOLS_DIR"
    echo "===================================================="

    install_base_system
    create_user
    create_tool_directories

    # Install profile APT tools
    echo "[+] Installing APT tools for profile: $PROFILE"
    PROFILE_TOOLS=$(get_profile_tools "$PROFILE")
    if [[ -n "$PROFILE_TOOLS" ]]; then
        # shellcheck disable=SC2086
        apt-get install -y $PROFILE_TOOLS || true
    fi

    # Install GitHub tools (parallel)
    install_profile_github_tools "$PROFILE"

    # Configure apps
    configure_applications

    # Security hardening
    harden_system

    # Cleanup
    apt-get autoremove -y --purge
    apt-get clean

    # Summary
    set +x
    echo
    echo "=================== KALIFORGE II COMPLETE ==================="
    echo " User:          $USER_NAME"
    echo " Profile:       $PROFILE"
    echo " Tools:         $TOOLS_DIR"
    if systemctl is-active --quiet ssh; then
        echo " SSH:           ENABLED on port $SSH_PORT (key-only, PAM off)"
    else
        echo " SSH:           DISABLED (no PUBKEY provided)"
    fi
    echo " Root locked:   yes"
    echo " Kali locked:   $(id -u kali >/dev/null 2>&1 && echo yes || echo n/a)"
    echo " Firewall:      active (ufw)"
    echo " Fail2ban:      active"
    echo " Log:           $LOG"
    echo "============================================================="
}

main "$@"
