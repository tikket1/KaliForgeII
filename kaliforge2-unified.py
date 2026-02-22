#!/usr/bin/env python3
"""
KaliForge II - Unified Security Environment Manager
Ncurses TUI for configuring and launching the Kali bootstrap script.
"""

import curses
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

STATE_FILE = Path('/etc/kaliforge2/state.json')


class KaliForgeUnified:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.height, self.width = stdscr.getmaxyx()

        self.config = {
            'USER_NAME': '',
            'SSH_PORT': '2222',
            'PROFILE': 'standard',
            'INSTALL_KDE': True,
            'PUBKEY': '',
            'GITHUB_TOKEN': '',
            'CURRENT_MODE': 'setup',
        }
        self._load_state()

        self.security_modes = {
            'hardened': {
                'name': 'Hardened Security',
                'description': 'Maximum security, minimal attack surface',
                'ufw_rules': [
                    'ufw --force reset',
                    'ufw default deny incoming',
                    'ufw default deny outgoing',
                    'ufw allow out 53',
                    'ufw allow out 80',
                    'ufw allow out 443',
                    'ufw allow out 123',
                ],
                'services': ['fail2ban'],
                'sysctl': {
                    'net.ipv4.ip_forward': '0',
                    'net.ipv4.conf.all.accept_redirects': '0',
                    'net.ipv4.conf.all.send_redirects': '0',
                    'net.ipv4.conf.all.log_martians': '1',
                },
            },
            'honeypot': {
                'name': 'Honeypot Mode',
                'description': 'Permissive firewall for threat research',
                'ufw_rules': [
                    'ufw --force reset',
                    'ufw default allow incoming',
                    'ufw default allow outgoing',
                ],
                'services': [],
                'sysctl': {
                    'net.ipv4.ip_forward': '1',
                    'net.ipv4.conf.all.accept_redirects': '1',
                    'net.ipv4.conf.all.send_redirects': '1',
                },
            },
            'stealth': {
                'name': 'Stealth Mode',
                'description': 'Minimal footprint, reduced logging',
                'ufw_rules': [
                    'ufw --force reset',
                    'ufw default deny incoming',
                    'ufw default allow outgoing',
                ],
                'services': [],
                'sysctl': {
                    'net.ipv4.ip_forward': '0',
                    'net.ipv4.conf.all.accept_source_route': '0',
                    'net.ipv4.conf.all.log_martians': '0',
                },
            },
            'pentest': {
                'name': 'Penetration Testing',
                'description': 'Optimized for active security testing',
                'ufw_rules': [
                    'ufw --force reset',
                    'ufw default deny incoming',
                    'ufw default allow outgoing',
                ],
                'services': [],
                'sysctl': {
                    'net.ipv4.ip_forward': '1',
                    'net.ipv4.conf.all.accept_redirects': '0',
                },
            },
        }

        self.init_colors()
        curses.curs_set(0)
        self.ascii_art = self.load_ascii_art()

    def _load_state(self):
        """Restore config from previous run if available."""
        try:
            if STATE_FILE.exists():
                with open(STATE_FILE, 'r') as f:
                    saved = json.load(f)
                # Only restore keys we care about (ignore stale keys)
                for key in ('USER_NAME', 'SSH_PORT', 'PROFILE',
                            'INSTALL_KDE', 'PUBKEY', 'CURRENT_MODE'):
                    if key in saved:
                        self.config[key] = saved[key]
        except (json.JSONDecodeError, OSError):
            pass

    def _save_state(self):
        """Persist non-secret config so the TUI survives restarts."""
        try:
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            # Never persist tokens/keys to disk
            safe = {k: v for k, v in self.config.items()
                    if k not in ('GITHUB_TOKEN', 'PUBKEY')}
            with open(STATE_FILE, 'w') as f:
                json.dump(safe, f, indent=2)
            os.chmod(str(STATE_FILE), 0o600)
        except OSError:
            pass

    def init_colors(self):
        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLUE)
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_YELLOW)

    def load_ascii_art(self):
        script_dir = Path(__file__).parent
        ascii_file = script_dir / "kaliforge2_ascii_terminal.txt"
        if ascii_file.exists():
            try:
                with open(ascii_file, 'r', encoding='utf-8') as f:
                    return f.read().splitlines()
            except Exception:
                pass
        return [
            "  KALIFORGE II",
            "  Unified Security Environment Manager",
        ]

    def draw_box(self, y, x, height, width, title=""):
        try:
            self.stdscr.addch(y, x, curses.ACS_ULCORNER)
            self.stdscr.addch(y, x + width - 1, curses.ACS_URCORNER)
            self.stdscr.addch(y + height - 1, x, curses.ACS_LLCORNER)
            self.stdscr.addch(y + height - 1, x + width - 1, curses.ACS_LRCORNER)
            for i in range(1, width - 1):
                self.stdscr.addch(y, x + i, curses.ACS_HLINE)
                self.stdscr.addch(y + height - 1, x + i, curses.ACS_HLINE)
            for i in range(1, height - 1):
                self.stdscr.addch(y + i, x, curses.ACS_VLINE)
                self.stdscr.addch(y + i, x + width - 1, curses.ACS_VLINE)
            if title:
                title_x = x + (width - len(title) - 4) // 2
                self.stdscr.addstr(y, title_x, f"[ {title} ]",
                                   curses.color_pair(1) | curses.A_BOLD)
        except curses.error:
            pass

    def show_header(self):
        self.height, self.width = self.stdscr.getmaxyx()
        self.stdscr.clear()
        start_y = 2
        art_height = len(self.ascii_art)
        for i, line in enumerate(self.ascii_art):
            if start_y + i < self.height - 1:
                x_pos = max(0, (self.width - len(line)) // 2)
                try:
                    color = curses.color_pair(5) if i >= art_height - 1 else curses.color_pair(1)
                    self.stdscr.addstr(start_y + i, x_pos, line, color | curses.A_BOLD)
                except curses.error:
                    pass
        if self.config['CURRENT_MODE'] != 'setup':
            mode_info = f"Current Mode: {self.security_modes[self.config['CURRENT_MODE']]['name']}"
            try:
                self.stdscr.addstr(1, 2, mode_info,
                                   curses.color_pair(7) | curses.A_BOLD)
            except curses.error:
                pass

    def show_menu(self, title, options, selected=0):
        menu_height = len(options) + 6
        menu_width = max(len(title) + 6, max(len(opt) for opt in options) + 6, 50)
        start_y = (self.height - menu_height) // 2
        start_x = (self.width - menu_width) // 2

        while True:
            self.show_header()
            self.draw_box(start_y, start_x, menu_height, menu_width, title)

            for i, option in enumerate(options):
                y_pos = start_y + 2 + i
                x_pos = start_x + 2
                try:
                    if i == selected:
                        self.stdscr.addstr(y_pos, x_pos, f"> {option}",
                                           curses.color_pair(6) | curses.A_BOLD)
                    else:
                        self.stdscr.addstr(y_pos, x_pos, f"  {option}",
                                           curses.color_pair(2))
                except curses.error:
                    pass

            try:
                self.stdscr.addstr(start_y + menu_height - 2, start_x + 2,
                                   "Up/Down: Navigate  ENTER: Select  ESC: Back",
                                   curses.color_pair(3))
            except curses.error:
                pass

            self.stdscr.refresh()
            key = self.stdscr.getch()

            if key == curses.KEY_UP:
                n = selected - 1
                while n >= 0 and options[n] == "":
                    n -= 1
                if n >= 0:
                    selected = n
            elif key == curses.KEY_DOWN:
                n = selected + 1
                while n < len(options) and options[n] == "":
                    n += 1
                if n < len(options):
                    selected = n
            elif key in (curses.KEY_ENTER, ord('\n'), ord('\r')):
                if options[selected] != "":
                    return selected
            elif key == 27:
                return -1

    def get_input(self, prompt, default="", password=False, input_type="general"):
        input_height = 8
        input_width = 70
        start_y = (self.height - input_height) // 2
        start_x = (self.width - input_width) // 2

        current_input = default
        error_msg = ""

        while True:
            self.show_header()
            self.draw_box(start_y, start_x, input_height, input_width, "Input")

            try:
                self.stdscr.addstr(start_y + 2, start_x + 2, prompt,
                                   curses.color_pair(1) | curses.A_BOLD)
                display = "*" * len(current_input) if password else current_input
                self.stdscr.addstr(start_y + 4, start_x + 2, f"> {display}",
                                   curses.color_pair(2))
                if error_msg:
                    truncated = error_msg[:input_width - 6]
                    self.stdscr.addstr(start_y + 6, start_x + 2, truncated,
                                       curses.color_pair(4))
                else:
                    self.stdscr.addstr(start_y + 6, start_x + 2,
                                       "ENTER: Confirm  ESC: Cancel",
                                       curses.color_pair(3))
            except curses.error:
                pass

            self.stdscr.refresh()
            key = self.stdscr.getch()

            if key in (curses.KEY_ENTER, ord('\n'), ord('\r')):
                val = current_input.strip() if current_input else default
                valid, msg = self._validate(val, input_type)
                if not valid:
                    error_msg = msg
                    continue
                return val
            elif key == 27:
                return default
            elif key in (curses.KEY_BACKSPACE, ord('\b'), 127):
                if current_input:
                    current_input = current_input[:-1]
                    error_msg = ""
            elif 32 <= key <= 126:
                max_len = {'username': 32, 'ssh_port': 5, 'ssh_key': 4096,
                           'github_token': 50}.get(input_type, 200)
                if len(current_input) < max_len:
                    current_input += chr(key)
                    error_msg = ""

    @staticmethod
    def _validate(value, input_type):
        if not value:
            return True, ""
        if input_type == 'username':
            if not re.match(r'^[a-z][a-z0-9_-]{2,31}$', value):
                return False, "3-32 chars, lowercase, start with letter"
        elif input_type == 'ssh_port':
            try:
                port = int(value)
                if not 1024 <= port <= 65535:
                    return False, "Port must be 1024-65535"
            except ValueError:
                return False, "Must be a number"
        elif input_type == 'ssh_key':
            prefixes = ('ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp')
            if not value.startswith(prefixes):
                return False, "Must start with ssh-rsa, ssh-ed25519, or ecdsa-sha2-nistp"
        elif input_type == 'github_token':
            if not value.startswith('ghp_'):
                return False, "Token must start with ghp_"
        return True, ""

    def show_message(self, title, message, msg_type="info"):
        lines = message.split('\n')
        msg_height = len(lines) + 6
        msg_width = max(len(title) + 6, max(len(line) for line in lines) + 6, 50)
        start_y = (self.height - msg_height) // 2
        start_x = (self.width - msg_width) // 2

        color_map = {"error": 4, "warning": 3}
        color = curses.color_pair(color_map.get(msg_type, 2))

        self.show_header()
        self.draw_box(start_y, start_x, msg_height, msg_width, title)

        for i, line in enumerate(lines):
            try:
                self.stdscr.addstr(start_y + 2 + i, start_x + 2, line, color)
            except curses.error:
                pass
        try:
            self.stdscr.addstr(start_y + msg_height - 2, start_x + 2,
                               "Press any key to continue...", curses.color_pair(3))
        except curses.error:
            pass

        self.stdscr.refresh()
        self.stdscr.getch()

    def initial_setup(self):
        self.show_message("Welcome to KaliForge II",
                          "This wizard will configure your Kali environment.\n\n"
                          "You will choose:\n"
                          "  - Username and SSH settings\n"
                          "  - Security profile\n"
                          "  - Desktop and GitHub options", "info")

        # Username
        username = self.get_input("Enter username:",
                                  os.getenv('SUDO_USER', os.getenv('USER', '')),
                                  input_type='username')
        if not username:
            self.show_message("Error", "Username is required.", "error")
            return False
        self.config['USER_NAME'] = username

        # SSH
        if self.show_menu("Configure SSH Access?", ["Yes, configure SSH", "No, disable SSH"]) == 0:
            ssh_port = self.get_input("SSH Port:", self.config['SSH_PORT'],
                                      input_type='ssh_port')
            self.config['SSH_PORT'] = ssh_port
            pubkey = self.get_input("SSH Public Key (paste your key):", "",
                                    input_type='ssh_key')
            if pubkey:
                self.config['PUBKEY'] = pubkey

        # Profile
        profiles = ["minimal", "webapp", "internal", "cloud", "standard", "heavy"]
        choice = self.show_menu("Select Security Profile", profiles)
        if choice >= 0:
            self.config['PROFILE'] = profiles[choice]

        # KDE
        self.config['INSTALL_KDE'] = self.show_menu("Install KDE Desktop?",
                                                     ["Yes, install KDE", "No, headless"]) == 0

        # GitHub token
        if self.show_menu("Add GitHub Token? (raises API limit from 60 to 5000/hr)",
                          ["Yes", "No, skip"]) == 0:
            token = self.get_input(
                "GitHub PAT (github.com/settings/tokens):", "",
                password=True, input_type='github_token')
            if token:
                self.config['GITHUB_TOKEN'] = token

        return self.confirm_setup()

    def confirm_setup(self):
        ssh_desc = ('Enabled on port ' + self.config['SSH_PORT']
                    if self.config['PUBKEY'] else 'Disabled')
        summary = [
            f"User: {self.config['USER_NAME']}",
            f"Profile: {self.config['PROFILE']}",
            f"SSH: {ssh_desc}",
            f"KDE Desktop: {'Yes' if self.config['INSTALL_KDE'] else 'No'}",
            f"GitHub: {'Configured' if self.config['GITHUB_TOKEN'] else 'Not configured'}",
        ]
        result = self.show_menu("Confirm Configuration",
                                summary + ["", "Proceed with Installation", "Cancel"])
        confirmed = result == len(summary) + 1
        if confirmed:
            self._save_state()
        return confirmed

    def execute_bootstrap(self):
        if not self.config.get('USER_NAME'):
            self.show_message("Error",
                              "Configuration incomplete. Run initial setup first.",
                              "error")
            return False

        self.show_message("Bootstrap",
                          "Starting system bootstrap...\n"
                          "The TUI will exit while the script runs.\n"
                          "Press any key to begin.",
                          "info")
        try:
            script = self.generate_bootstrap_script()
            tmp_path = '/tmp/kaliforge2_bootstrap.sh'
            with open(tmp_path, 'w') as f:
                f.write(script)
            os.chmod(tmp_path, 0o755)

            # Exit curses so bootstrap output is visible in real time
            curses.endwin()
            print("\n=== KaliForge II Bootstrap ===\n")
            returncode = subprocess.call(['bash', tmp_path])

            try:
                os.unlink(tmp_path)
            except OSError:
                pass

            if returncode == 0:
                print("\n[+] Bootstrap completed successfully.")
            else:
                print(f"\n[!] Bootstrap exited with code {returncode}.")
            print("\nPress ENTER to return to the TUI...")
            input()

            # Re-initialize curses
            self.stdscr = curses.initscr()
            curses.noecho()
            curses.cbreak()
            self.stdscr.keypad(True)
            self.init_colors()
            curses.curs_set(0)
            self.height, self.width = self.stdscr.getmaxyx()

            return returncode == 0

        except Exception as e:
            # Ensure curses is restored even on error
            try:
                self.stdscr = curses.initscr()
                curses.noecho()
                curses.cbreak()
                self.stdscr.keypad(True)
                self.init_colors()
                curses.curs_set(0)
                self.height, self.width = self.stdscr.getmaxyx()
            except Exception:
                pass
            self.show_message("Error", f"Bootstrap failed: {e}", "error")
            return False

    def generate_bootstrap_script(self):
        script_dir = Path(__file__).parent
        kde = str(self.config['INSTALL_KDE']).lower()

        return f'''#!/bin/bash
set -euo pipefail
export USER_NAME={shlex.quote(self.config['USER_NAME'])}
export SSH_PORT={shlex.quote(self.config['SSH_PORT'])}
export PROFILE={shlex.quote(self.config['PROFILE'])}
export INSTALL_KDE={shlex.quote(kde)}
export PUBKEY={shlex.quote(self.config['PUBKEY'])}
export GITHUB_TOKEN={shlex.quote(self.config['GITHUB_TOKEN'])}
export MAX_PARALLEL_DOWNLOADS=4
export ALLOWLIST_CIDR={shlex.quote(os.environ.get('ALLOWLIST_CIDR', ''))}
export DISABLE_IPV6={shlex.quote(os.environ.get('DISABLE_IPV6', 'false'))}
export VERBOSE={shlex.quote(os.environ.get('VERBOSE', 'false'))}

echo "Starting KaliForge II Bootstrap..."
echo "  User: $USER_NAME"
echo "  Profile: $PROFILE"

if [[ -f {shlex.quote(str(script_dir / "kaliforge2.sh"))} ]]; then
    bash {shlex.quote(str(script_dir / "kaliforge2.sh"))}
else
    echo "Error: kaliforge2.sh not found!"
    exit 1
fi
'''

    def mode_switcher(self):
        while True:
            current_mode = self.config.get('CURRENT_MODE', 'setup')
            menu_options = []
            for mode_key, mode_info in self.security_modes.items():
                status = " (ACTIVE)" if mode_key == current_mode else ""
                menu_options.append(f"{mode_info['name']}{status}")
            menu_options.extend(["", "Back to Main Menu"])

            choice = self.show_menu("Security Mode Switcher", menu_options)
            if choice == -1 or choice >= len(self.security_modes):
                break

            mode_keys = list(self.security_modes.keys())
            selected = mode_keys[choice]
            if self.confirm_mode_switch(selected):
                self.apply_security_mode(selected)

    def confirm_mode_switch(self, mode):
        info = self.security_modes[mode]
        self.show_message(
            f"Switch to {info['name']}?",
            f"{info['description']}\n\n"
            "This will modify:\n"
            "  - Firewall rules (UFW)\n"
            "  - Sysctl network settings\n"
            "  - System services",
            "warning")
        result = self.show_menu("Apply changes?",
                                ["Apply Changes", "Cancel"])
        return result == 0

    def _get_ssh_ufw_rule(self):
        """Read the live SSH port and return a ufw allow rule, or None."""
        try:
            r = subprocess.run(
                ['ss', '-tlnp'], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if 'sshd' in line:
                    # extract port from *:PORT or 0.0.0.0:PORT
                    for field in line.split():
                        if ':' in field:
                            port = field.rsplit(':', 1)[-1]
                            if port.isdigit():
                                return f'ufw limit {port}/tcp'
        except Exception:
            pass
        # Fallback: check if ssh is active and use config SSH_PORT
        try:
            r = subprocess.run(
                ['systemctl', 'is-active', 'ssh'],
                capture_output=True, text=True, timeout=5)
            if r.stdout.strip() == 'active':
                port = self.config.get('SSH_PORT', '2222')
                return f'ufw limit {port}/tcp'
        except Exception:
            pass
        return None

    def apply_security_mode(self, mode):
        info = self.security_modes[mode]
        errors = []

        # Snapshot current UFW rules for rollback
        try:
            backup = subprocess.run(
                ['ufw', 'status', 'numbered'],
                capture_output=True, text=True, timeout=10)
            ufw_backup = backup.stdout
        except Exception:
            ufw_backup = None

        # Detect SSH rule to re-apply after reset
        ssh_rule = self._get_ssh_ufw_rule()

        try:
            # UFW rules
            for rule in info['ufw_rules']:
                subprocess.run(rule.split(), check=True,
                               capture_output=True, timeout=30)

            # Re-apply SSH access after the reset
            if ssh_rule:
                subprocess.run(ssh_rule.split(), check=False,
                               capture_output=True, timeout=30)

            subprocess.run(['ufw', '--force', 'enable'], check=True,
                           capture_output=True, timeout=30)

        except subprocess.CalledProcessError as e:
            errors.append(f"UFW: {e}")
            # Attempt rollback: re-enable with whatever state remains
            subprocess.run(['ufw', '--force', 'enable'],
                           capture_output=True, timeout=30)

        # Sysctl — apply runtime + persist to file
        sysctl_path = '/etc/sysctl.d/99-kaliforge-mode.conf'
        sysctl_lines = []
        for key, value in info.get('sysctl', {}).items():
            r = subprocess.run(['sysctl', '-w', f'{key}={value}'],
                               capture_output=True, timeout=15)
            if r.returncode != 0:
                errors.append(f"sysctl {key}: {r.stderr.decode().strip()}")
            sysctl_lines.append(f'{key} = {value}')

        try:
            with open(sysctl_path, 'w') as f:
                f.write(f'# KaliForge II mode: {mode}\n')
                f.write('\n'.join(sysctl_lines) + '\n')
        except OSError as e:
            errors.append(f"sysctl persist: {e}")

        # Services
        for service in info.get('services', []):
            subprocess.run(['systemctl', 'enable', '--now', service],
                           capture_output=True, timeout=30)

        self.config['CURRENT_MODE'] = mode
        self._save_state()

        if errors:
            self.show_message("Mode Partially Applied",
                              f"Switched to {info['name']} with warnings:\n" +
                              "\n".join(errors),
                              "warning")
        else:
            self.show_message("Mode Applied",
                              f"Switched to {info['name']}", "info")

    def show_system_status(self):
        status_info = []
        checks = [
            ("Firewall (UFW)", ['ufw', 'status']),
            ("SSH Service", ['systemctl', 'is-active', 'ssh']),
            ("Fail2ban", ['systemctl', 'is-active', 'fail2ban']),
        ]
        for label, cmd in checks:
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                out = r.stdout.strip()
                if 'status' in cmd:
                    val = "Active" if "Status: active" in out else "Inactive"
                else:
                    val = out
                status_info.append(f"{label}: {val}")
            except Exception:
                status_info.append(f"{label}: unknown")

        status_info.append(f"Current User: {os.getenv('SUDO_USER', os.getenv('USER', 'unknown'))}")

        try:
            r = subprocess.run(['uptime'], capture_output=True, text=True, timeout=5)
            load = r.stdout.strip().split('load average: ')[-1]
            status_info.append(f"Load Average: {load}")
        except Exception:
            pass

        current_mode = self.config.get('CURRENT_MODE', 'setup')
        if current_mode in self.security_modes:
            status_info.append(f"Security Mode: {self.security_modes[current_mode]['name']}")

        self.show_message("System Status", "\n".join(status_info), "info")

    def main_menu(self):
        while True:
            is_setup = not self.config.get('USER_NAME')

            if is_setup:
                options = [
                    "Initial System Setup",
                    "Exit",
                ]
            else:
                options = [
                    "Security Mode Switcher",
                    "Re-run Bootstrap",
                    "System Status",
                    "Exit",
                ]

            choice = self.show_menu("KaliForge II - Main Menu", options)

            if choice == -1 or choice == len(options) - 1:
                break
            elif choice == 0:
                if is_setup:
                    if self.initial_setup():
                        if self.show_menu("Execute Bootstrap?",
                                          ["Yes, run bootstrap", "No, later"]) == 0:
                            self.execute_bootstrap()
                        self.show_message("Setup Complete",
                                          "Initial setup done.\n\n"
                                          "Use Security Mode Switcher to\n"
                                          "reconfigure your system.", "info")
                else:
                    self.mode_switcher()
            elif choice == 1 and not is_setup:
                self.execute_bootstrap()
            elif choice == 2 and not is_setup:
                self.show_system_status()

    def run(self):
        try:
            self.main_menu()
        except KeyboardInterrupt:
            pass
        finally:
            curses.curs_set(1)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description='KaliForge II - Unified Security Environment Manager')
    parser.add_argument('--no-root-check', action='store_true',
                        help='Skip root privilege check (for testing)')
    parser.add_argument('--version', action='version', version='KaliForge II v2.0')
    args = parser.parse_args()

    if not args.no_root_check and os.geteuid() != 0:
        print("This script requires root privileges. Run with sudo.")
        print("Use --no-root-check for UI testing only.")
        sys.exit(1)

    curses.wrapper(lambda stdscr: KaliForgeUnified(stdscr).run())


if __name__ == "__main__":
    main()
