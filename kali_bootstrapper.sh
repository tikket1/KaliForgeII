#!/usr/bin/env bash
# kali_bootstrapper.sh (final-final) — SSH hardened: key-only, PAM off, root off
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
LOG="/var/log/kali_bootstrapper.log"
exec > >(tee -a "$LOG") 2>&1
set -x
trap 'echo "ERROR at line $LINENO: $BASH_COMMAND"; exit 1' ERR

# -------------------- Config --------------------
USER_NAME="${USER_NAME:-tikket}"
SSH_PORT="${SSH_PORT:-2222}"
ALLOWLIST_CIDR="${ALLOWLIST_CIDR:-}"
DISABLE_IPV6="${DISABLE_IPV6:-false}"
INSTALL_KDE="${INSTALL_KDE:-true}"
TOOLS_HEAVY="${TOOLS_HEAVY:-true}"
PUBKEY="${PUBKEY:-}"

# -------------------- Repo key & sources fix ----
apt-get clean
apt-get update || true
apt-get install -y --no-install-recommends ca-certificates gnupg curl wget apt-transport-https

install -d -m 755 /usr/share/keyrings
curl -fsSL https://archive.kali.org/archive-key.asc | gpg --dearmor -o /usr/share/keyrings/kali-archive-keyring.gpg
chmod 644 /usr/share/keyrings/kali-archive-keyring.gpg

if ! grep -q "kali-rolling" /etc/apt/sources.list; then
cat >/etc/apt/sources.list <<'EOF'
deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main non-free contrib
EOF
fi

apt-get -y -f install   # ensure fix-broken packages
apt-get update -y

# -------------------- Helpers -------------------
gen_password() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 48 | tr -dc 'A-Za-z0-9!@#%^*_+=_' | head -c 28
  else
    dd if=/dev/urandom bs=1 count=64 2>/dev/null | base64 | tr -dc 'A-Za-z0-9!@#%^*_+=_' | head -c 28
  fi
}

# -------------------- User ----------------------
if id -u "$USER_NAME" >/dev/null 2>&1; then
  echo "[i] User $USER_NAME already exists."
else
  adduser --disabled-password --gecos "" "$USER_NAME"
  CONSOLE_PASS="$(gen_password)"
  echo "$USER_NAME:$CONSOLE_PASS" | chpasswd
fi

# -------------------- Base packages -------------
apt-get dist-upgrade -y
apt-get install -y \
  sudo ufw fail2ban unattended-upgrades apt-listchanges \
  build-essential git curl wget unzip xz-utils jq \
  net-tools dnsutils iproute2 iputils-ping traceroute \
  zsh tmux htop neovim fontconfig \
  open-vm-tools open-vm-tools-desktop \
  openssh-server

systemctl enable --now open-vm-tools.service || true

# -------------------- Unattended upgrades -------
dpkg-reconfigure -f noninteractive unattended-upgrades
cat >/etc/apt/apt.conf.d/51unattended-upgrades-kali <<'EOF'
Unattended-Upgrade::Origins-Pattern { "o=Kali,a=kali-rolling"; };
Unattended-Upgrade::Automatic-Reboot "false";
EOF
systemctl enable --now unattended-upgrades.service

# -------------------- Optional KDE --------------
if [[ "$INSTALL_KDE" == "true" ]]; then
  if ! dpkg -l | grep -q kali-desktop-kde; then
    apt-get install -y kali-desktop-kde sddm
    debconf-set-selections <<< "sddm shared/default-x-display-manager select sddm"
    dpkg-reconfigure -f noninteractive sddm || true
  fi
fi

# -------------------- Wireshark -----------------
echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
apt-get install -y wireshark
usermod -aG wireshark "$USER_NAME" || true
if command -v dumpcap >/dev/null 2>&1; then
  chgrp wireshark "$(command -v dumpcap)"
  chmod 750 "$(command -v dumpcap)"
  setcap cap_net_raw,cap_net_admin+eip "$(command -v dumpcap)" || true
fi

# -------------------- Tooling -------------------
TOOLS=( nmap gobuster seclists ffuf feroxbuster
        sqlmap wpscan whatweb amass
        mitmproxy
        netcat-traditional socat tcpdump masscan
        crackmapexec impacket-scripts smbclient smbmap
        docker.io docker-compose-plugin
        burpsuite )
if [[ "$TOOLS_HEAVY" == "true" ]]; then TOOLS+=( bloodhound neo4j ); fi
apt-get install -y "${TOOLS[@]}" || true
systemctl disable neo4j.service || true
systemctl enable --now docker || true
usermod -aG docker "$USER_NAME" || true

# -------------------- Root & kali lockdown ------
passwd -l root || true
if id -u kali >/dev/null 2>&1; then
  passwd -l kali || true
  usermod -L kali || true
fi

# -------------------- Sudo hardening ------------
usermod -aG sudo "$USER_NAME" || true
cat >/etc/sudoers.d/90-secure-sudo <<'EOF'
Defaults env_reset,timestamp_timeout=5,log_input,log_output
Defaults passwd_tries=3,badpass_message="sudo: authentication failed"
EOF
chmod 440 /etc/sudoers.d/90-secure-sudo

# -------------------- SSH (only if PUBKEY) ------
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

# -------------------- UFW firewall --------------
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

# -------------------- Fail2ban -------------------
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

# -------------------- Sysctl hardening ----------
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

# -------------------- Service hygiene -----------
systemctl disable --now avahi-daemon || true
systemctl disable --now cups || true
systemctl disable --now rpcbind || true
systemctl disable --now neo4j || true

# -------------------- Cleanup -------------------
apt-get autoremove -y --purge
apt-get clean

# -------------------- Summary -------------------
set +x
echo
echo "===================== SECURE KALI BOOTSTRAP COMPLETE ====================="
echo " User:          $USER_NAME"
if systemctl is-active --quiet ssh; then
  echo " SSH:           ENABLED on port $SSH_PORT (key-only, PAM off)"
else
  echo " SSH:           DISABLED (no PUBKEY provided)"
fi
echo " Root locked:   yes"
echo " 'kali' locked: $(if id -u kali >/dev/null 2>&1; then echo yes; else echo n/a; fi)"
echo "========================================================================="
