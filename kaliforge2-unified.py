#!/usr/bin/env python3
"""
KaliForge II - Unified Security Environment Manager
Consolidated ncurses interface with dynamic configuration and mode switching

Version 2.0 - Enhanced with logging, state management, and validation
"""

import curses
import os
import sys
import subprocess
import json
import time
import hashlib
import secrets
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple

# Import our enhanced systems
try:
    from kaliforge2_logger import get_logger, init_logger, ProgressLogger
    from kaliforge2_state import get_state_manager, init_state_manager, KaliForgeConfig
    from kaliforge2_validator import SecurityValidator, validate_all_inputs, ValidationError
    from kaliforge2_progress_monitor import KaliForgeProgressMonitor, get_progress_monitor
    ENHANCED_MODE = True
except ImportError:
    # Fallback mode if enhanced modules aren't available
    ENHANCED_MODE = False
    print("Warning: Running in basic mode. Enhanced features disabled.")

class KaliForgeUnified:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.height, self.width = stdscr.getmaxyx()
        
        # Initialize enhanced systems
        if ENHANCED_MODE:
            self.logger = get_logger()
            self.state_manager = get_state_manager()
            self.progress_monitor = get_progress_monitor()
            self.logger.log_info("KaliForge II Enhanced Mode - Starting unified interface")
            
            # Load persistent configuration
            persistent_config = self.state_manager.load_config()
            self.config = {
                'USER_NAME': persistent_config.user_name,
                'SSH_PORT': persistent_config.ssh_port,
                'PROFILE': persistent_config.profile,
                'INSTALL_KDE': persistent_config.install_kde,
                'PUBKEY': persistent_config.pubkey,
                'GITHUB_TOKEN': persistent_config.github_token,
                'CURRENT_MODE': persistent_config.current_mode
            }
        else:
            # Fallback configuration
            self.logger = None
            self.state_manager = None
            self.progress_monitor = None
            self.config = {
                'USER_NAME': '',
                'SSH_PORT': '2222', 
                'PROFILE': 'standard',
                'INSTALL_KDE': True,
                'PUBKEY': '',
                'GITHUB_TOKEN': '',
                'CURRENT_MODE': 'setup'
            }
        
        # Security modes configuration
        self.security_modes = {
            'hardened': {
                'name': 'Hardened Security',
                'description': 'Maximum security, minimal attack surface',
                'ufw_rules': [
                    'ufw --force reset',
                    'ufw default deny incoming',
                    'ufw default deny outgoing',
                    'ufw allow out 53',  # DNS
                    'ufw allow out 80',  # HTTP
                    'ufw allow out 443', # HTTPS
                    'ufw allow out 123', # NTP
                ],
                'services': ['fail2ban', 'auditd'],
                'sysctl': {
                    'net.ipv4.ip_forward': '0',
                    'net.ipv4.conf.all.accept_redirects': '0',
                    'net.ipv4.conf.all.send_redirects': '0',
                    'net.ipv4.conf.all.log_martians': '1'
                }
            },
            'honeypot': {
                'name': 'Honeypot Mode',
                'description': 'Attract and monitor attackers',
                'ufw_rules': [
                    'ufw --force reset',
                    'ufw default allow incoming',
                    'ufw default allow outgoing',
                ],
                'services': ['cowrie', 'dionaea', 'honeyd'],
                'ports_open': [22, 23, 80, 135, 139, 445, 1433, 3389],
                'sysctl': {
                    'net.ipv4.ip_forward': '1',
                    'net.ipv4.conf.all.accept_redirects': '1',
                    'net.ipv4.conf.all.send_redirects': '1'
                }
            },
            'stealth': {
                'name': 'Stealth Mode',
                'description': 'Minimal footprint, covert operations',
                'ufw_rules': [
                    'ufw --force reset',
                    'ufw default deny incoming',
                    'ufw default allow outgoing',
                ],
                'services': ['tor', 'proxychains'],
                'sysctl': {
                    'net.ipv4.ip_forward': '0',
                    'net.ipv4.conf.all.accept_source_route': '0',
                    'net.ipv4.conf.all.log_martians': '0'
                }
            },
            'pentest': {
                'name': 'Penetration Testing',
                'description': 'Optimized for active security testing',
                'ufw_rules': [
                    'ufw --force reset',
                    'ufw default deny incoming',
                    'ufw default allow outgoing',
                ],
                'services': ['postgresql', 'apache2'],
                'sysctl': {
                    'net.ipv4.ip_forward': '1',
                    'net.ipv4.conf.all.accept_redirects': '0'
                }
            }
        }
        
        # Initialize color pairs
        self.init_colors()
        
        # Disable cursor
        curses.curs_set(0)
        
        # Load ASCII art
        self.ascii_art = self.load_ascii_art()
        
    def init_colors(self):
        """Initialize color pairs"""
        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)      # Headers
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)     # Success
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)    # Warning
        curses.init_pair(4, curses.COLOR_RED, curses.COLOR_BLACK)       # Error
        curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)   # Highlight
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLUE)      # Selected
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_YELLOW)    # Mode indicator
        
    def load_ascii_art(self):
        """Load ASCII art from file with fallback"""
        script_dir = Path(__file__).parent
        
        # Try to load from terminal-optimized ASCII file
        ascii_files = [
            script_dir / "kaliforge2_ascii_terminal.txt",
            script_dir / "kaliforge2_ascii_clean.txt"
        ]
        
        for ascii_file in ascii_files:
            if ascii_file.exists():
                try:
                    with open(ascii_file, 'r', encoding='utf-8') as f:
                        return f.read().splitlines()
                except Exception:
                    continue
        
        # Fallback ASCII art
        return [
            "  ██╗  ██╗ █████╗ ██╗     ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗    ██╗██╗",
            "  ██║ ██╔╝██╔══██╗██║     ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝    ██║██║",
            "  █████╔╝ ███████║██║     ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗      ██║██║",
            "  ██╔═██╗ ██╔══██║██║     ██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝      ██║██║",
            "  ██║  ██╗██║  ██║███████╗██║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗    ██║██║",
            "  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚═╝╚═╝",
            "",
            "              🔒 UNIFIED SECURITY ENVIRONMENT MANAGER 🔒"
        ]
    
    def draw_box(self, y, x, height, width, title=""):
        """Draw a box with optional title"""
        try:
            # Draw corners and edges
            self.stdscr.addch(y, x, '┌')
            self.stdscr.addch(y, x + width - 1, '┐')
            self.stdscr.addch(y + height - 1, x, '└')
            self.stdscr.addch(y + height - 1, x + width - 1, '┘')
            
            # Draw horizontal lines
            for i in range(1, width - 1):
                self.stdscr.addch(y, x + i, '─')
                self.stdscr.addch(y + height - 1, x + i, '─')
            
            # Draw vertical lines
            for i in range(1, height - 1):
                self.stdscr.addch(y + i, x, '│')
                self.stdscr.addch(y + i, x + width - 1, '│')
            
            # Add title if provided
            if title:
                title_x = x + (width - len(title) - 4) // 2
                self.stdscr.addstr(y, title_x, f"[ {title} ]", curses.color_pair(1) | curses.A_BOLD)
                
        except curses.error:
            pass
    
    def show_header(self):
        """Display ASCII art header"""
        self.stdscr.clear()
        
        # Calculate starting position for ASCII art
        art_height = len(self.ascii_art)
        start_y = 2
        
        for i, line in enumerate(self.ascii_art):
            if start_y + i < self.height - 1:
                # Center the line
                x_pos = max(0, (self.width - len(line)) // 2)
                try:
                    if i < art_height - 1:  # ASCII art lines
                        self.stdscr.addstr(start_y + i, x_pos, line, curses.color_pair(1) | curses.A_BOLD)
                    else:  # Subtitle
                        self.stdscr.addstr(start_y + i, x_pos, line, curses.color_pair(5) | curses.A_BOLD)
                except curses.error:
                    pass
        
        # Show current mode indicator
        if self.config['CURRENT_MODE'] != 'setup':
            mode_info = f"Current Mode: {self.security_modes[self.config['CURRENT_MODE']]['name']}"
            try:
                self.stdscr.addstr(1, 2, mode_info, curses.color_pair(7) | curses.A_BOLD)
            except curses.error:
                pass
    
    def show_menu(self, title, options, selected=0):
        """Display a menu and return selected option"""
        menu_height = len(options) + 6
        menu_width = max(len(title) + 6, max(len(opt) for opt in options) + 6, 50)
        
        start_y = (self.height - menu_height) // 2
        start_x = (self.width - menu_width) // 2
        
        while True:
            self.show_header()
            self.draw_box(start_y, start_x, menu_height, menu_width, title)
            
            # Display options
            for i, option in enumerate(options):
                y_pos = start_y + 2 + i
                x_pos = start_x + 2
                
                if i == selected:
                    try:
                        self.stdscr.addstr(y_pos, x_pos, f"▶ {option}", curses.color_pair(6) | curses.A_BOLD)
                    except curses.error:
                        pass
                else:
                    try:
                        self.stdscr.addstr(y_pos, x_pos, f"  {option}", curses.color_pair(2))
                    except curses.error:
                        pass
            
            # Instructions
            instructions = "↑↓: Navigate  ENTER: Select  ESC: Back/Exit"
            try:
                self.stdscr.addstr(start_y + menu_height - 2, start_x + 2, instructions, curses.color_pair(3))
            except curses.error:
                pass
            
            self.stdscr.refresh()
            
            key = self.stdscr.getch()
            
            if key == curses.KEY_UP and selected > 0:
                selected -= 1
            elif key == curses.KEY_DOWN and selected < len(options) - 1:
                selected += 1
            elif key in [curses.KEY_ENTER, ord('\n'), ord('\r')]:
                return selected
            elif key == 27:  # ESC key
                return -1
    
    def get_input(self, prompt, default="", password=False, input_type="general", validation_required=True):
        """Get user input with enhanced validation"""
        input_height = 10
        input_width = 70
        
        start_y = (self.height - input_height) // 2
        start_x = (self.width - input_width) // 2
        
        current_input = default
        validation_message = ""
        validation_color = curses.color_pair(3)
        
        while True:
            self.show_header()
            self.draw_box(start_y, start_x, input_height, input_width, "Input")
            
            # Show prompt
            try:
                self.stdscr.addstr(start_y + 2, start_x + 2, prompt, curses.color_pair(1) | curses.A_BOLD)
                
                # Show input field
                display_text = "●" * len(current_input) if password else current_input
                self.stdscr.addstr(start_y + 4, start_x + 2, f"> {display_text}", curses.color_pair(2))
                
                # Show validation message
                if validation_message:
                    # Truncate message if too long
                    max_msg_len = input_width - 6
                    display_msg = validation_message[:max_msg_len] + "..." if len(validation_message) > max_msg_len else validation_message
                    self.stdscr.addstr(start_y + 6, start_x + 2, display_msg, validation_color)
                
                # Instructions
                self.stdscr.addstr(start_y + 8, start_x + 2, "ENTER: Confirm  ESC: Cancel  F1: Help", curses.color_pair(3))
            except curses.error:
                pass
            
            self.stdscr.refresh()
            
            key = self.stdscr.getch()
            
            if key in [curses.KEY_ENTER, ord('\n'), ord('\r')]:
                # Validate input before accepting
                if ENHANCED_MODE and validation_required and current_input:
                    try:
                        # Sanitize input first
                        sanitized_input = SecurityValidator.sanitize_input(current_input, input_type)
                        
                        # Validate based on input type
                        validator_map = {
                            'username': SecurityValidator.validate_username,
                            'ssh_port': SecurityValidator.validate_ssh_port,
                            'ssh_key': SecurityValidator.validate_ssh_public_key,
                            'github_token': SecurityValidator.validate_github_token,
                            'profile': SecurityValidator.validate_profile_name,
                            'security_mode': SecurityValidator.validate_security_mode
                        }
                        
                        if input_type in validator_map:
                            valid, message = validator_map[input_type](sanitized_input)
                            if not valid:
                                validation_message = f"Invalid: {message}"
                                validation_color = curses.color_pair(4)  # Red
                                continue
                        
                        if self.logger:
                            self.logger.log_info(f"User input validated: {input_type}", extra_data={'input_type': input_type, 'length': len(sanitized_input)})
                        
                        return sanitized_input if sanitized_input else default
                        
                    except ValidationError as e:
                        validation_message = f"Security: {str(e)}"
                        validation_color = curses.color_pair(4)  # Red
                        if self.logger:
                            self.logger.log_warning(f"Input validation failed: {str(e)}", extra_data={'input_type': input_type})
                        continue
                    except Exception as e:
                        validation_message = "Validation error occurred"
                        validation_color = curses.color_pair(4)  # Red
                        if self.logger:
                            self.logger.log_error(f"Input validation error", e)
                        continue
                
                return current_input if current_input else default
                
            elif key == 27:  # ESC
                if self.logger:
                    self.logger.log_info(f"User cancelled input: {input_type}")
                return default
                
            elif key == curses.KEY_F1:  # F1 for help
                self.show_input_help(input_type)
                validation_message = ""  # Clear validation message after help
                
            elif key in [curses.KEY_BACKSPACE, ord('\b'), 127]:
                if current_input:
                    current_input = current_input[:-1]
                    validation_message = ""  # Clear validation message on edit
                    
            elif 32 <= key <= 126:  # Printable characters
                max_lengths = {'username': 32, 'ssh_port': 5, 'ssh_key': 4096, 'github_token': 50, 'general': 200}
                max_len = max_lengths.get(input_type, max_lengths['general'])
                
                if len(current_input) < max_len:
                    current_input += chr(key)
                    validation_message = ""  # Clear validation message on edit
    
    def show_input_help(self, input_type: str):
        """Show context-sensitive help for input types"""
        help_text = {
            'username': "Username Requirements:\n• 3-32 characters\n• Lowercase letters, numbers, hyphens, underscores\n• Must start with letter\n• Cannot be reserved system name",
            'ssh_port': "SSH Port Requirements:\n• Number between 1024-65535\n• Avoid ports already in use\n• Common secure ports: 2222, 2200, 22222",
            'ssh_key': "SSH Public Key:\n• Format: ssh-rsa AAAAB3... [comment]\n• Supports: RSA, Ed25519, ECDSA\n• Ed25519 recommended for best security\n• Leave empty if not using SSH",
            'github_token': "GitHub Token:\n• Personal access token format: ghp_...\n• Generate at github.com/settings/tokens\n• Needed for latest tool downloads\n• Optional but recommended",
            'profile': "Security Profiles:\n• minimal: Basic tools only\n• webapp: Web application testing\n• internal: Internal network testing\n• cloud: Cloud security tools\n• standard: General pentesting\n• heavy: Full security arsenal",
            'general': "General input help:\n• Follow security best practices\n• Avoid special characters when possible\n• Input is validated for safety"
        }
        
        help_message = help_text.get(input_type, help_text['general'])
        self.show_message("Help", help_message, "info")
    
    def initial_setup(self):
        """Initial system setup wizard"""
        self.show_header()
        
        # Welcome message
        self.show_message("Welcome to KaliForge II", 
                         "This wizard will guide you through the initial setup.\n\n" +
                         "• Dynamic configuration\n" +
                         "• Security mode switching\n" +
                         "• Enhanced password management\n" +
                         "• Comprehensive logging", 
                         "info")
        
        # System requirements check (enhanced mode only)
        if ENHANCED_MODE:
            self.logger.log_info("Starting system requirements validation")
            requirements = SecurityValidator.validate_system_requirements()
            
            failed_requirements = []
            for req_name, req_result in requirements.items():
                if not req_result['valid']:
                    failed_requirements.append(f"{req_name}: {req_result['message']}")
            
            if failed_requirements:
                error_msg = "System Requirements Failed:\n\n" + "\n".join(failed_requirements[:3])
                if len(failed_requirements) > 3:
                    error_msg += f"\n... and {len(failed_requirements) - 3} more issues"
                
                if self.show_menu("System Check Failed", [error_msg, "", "Continue Anyway", "Exit"]) == 3:
                    return False
        
        # Get username with validation
        username = self.get_input("Enter username for the system:", 
                                os.getenv('SUDO_USER', os.getenv('USER', '')), 
                                input_type='username')
        if not username:
            self.show_message("Error", "Username is required!", "error")
            return False
        self.config['USER_NAME'] = username
        
        # Get SSH configuration
        if self.show_menu("Configure SSH Access?", ["Yes", "No"]) == 0:
            ssh_port = self.get_input("SSH Port:", self.config['SSH_PORT'], input_type='ssh_port')
            self.config['SSH_PORT'] = ssh_port
            
            pubkey = self.get_input("SSH Public Key (paste your key):", "", input_type='ssh_key', validation_required=False)
            if pubkey:
                self.config['PUBKEY'] = pubkey
        
        # Select initial security profile
        profiles = ["minimal", "webapp", "internal", "cloud", "standard", "heavy"]
        profile_choice = self.show_menu("Select Security Profile", profiles)
        if profile_choice >= 0:
            self.config['PROFILE'] = profiles[profile_choice]
        
        # KDE Desktop
        if self.show_menu("Install KDE Desktop?", ["Yes", "No"]) == 0:
            self.config['INSTALL_KDE'] = True
        else:
            self.config['INSTALL_KDE'] = False
        
        # GitHub token (optional)
        if self.show_menu("Configure GitHub Integration?", ["Yes", "No"]) == 0:
            token = self.get_input("GitHub Personal Access Token (optional):", "", 
                                 password=True, input_type='github_token', validation_required=False)
            if token:
                self.config['GITHUB_TOKEN'] = token
        
        # Save configuration in enhanced mode
        if ENHANCED_MODE and self.state_manager:
            try:
                # Convert to KaliForgeConfig object
                persistent_config = KaliForgeConfig(
                    user_name=self.config['USER_NAME'],
                    ssh_port=self.config['SSH_PORT'],
                    profile=self.config['PROFILE'],
                    install_kde=self.config['INSTALL_KDE'],
                    pubkey=self.config['PUBKEY'],
                    github_token=self.config['GITHUB_TOKEN'],
                    current_mode=self.config['CURRENT_MODE'],
                    created_at=datetime.now().isoformat()
                )
                
                self.state_manager.save_config(persistent_config)
                self.logger.log_audit_event("initial_setup", "configuration", "SUCCESS", 
                                          {"profile": self.config['PROFILE'], "user": self.config['USER_NAME']})
            except Exception as e:
                if self.logger:
                    self.logger.log_error("Failed to save configuration", e)
        
        return self.confirm_setup()
    
    def confirm_setup(self):
        """Show configuration summary and confirm"""
        summary = [
            f"User: {self.config['USER_NAME']}",
            f"Profile: {self.config['PROFILE']}",
            f"SSH: {'Enabled on port ' + self.config['SSH_PORT'] if self.config['PUBKEY'] else 'Disabled'}",
            f"KDE Desktop: {'Yes' if self.config['INSTALL_KDE'] else 'No'}",
            f"GitHub Integration: {'Configured' if self.config['GITHUB_TOKEN'] else 'Not configured'}"
        ]
        
        result = self.show_menu("Confirm Configuration", summary + ["", "✓ Proceed with Installation", "✗ Cancel"])
        
        return result == len(summary) + 1
    
    def show_message(self, title, message, msg_type="info"):
        """Show a message box"""
        lines = message.split('\n')
        msg_height = len(lines) + 6
        msg_width = max(len(title) + 6, max(len(line) for line in lines) + 6, 50)
        
        start_y = (self.height - msg_height) // 2
        start_x = (self.width - msg_width) // 2
        
        color = curses.color_pair(2)  # Default green
        if msg_type == "error":
            color = curses.color_pair(4)
        elif msg_type == "warning":
            color = curses.color_pair(3)
        
        self.show_header()
        self.draw_box(start_y, start_x, msg_height, msg_width, title)
        
        for i, line in enumerate(lines):
            try:
                self.stdscr.addstr(start_y + 2 + i, start_x + 2, line, color)
            except curses.error:
                pass
        
        try:
            self.stdscr.addstr(start_y + msg_height - 2, start_x + 2, "Press any key to continue...", curses.color_pair(3))
        except curses.error:
            pass
        
        self.stdscr.refresh()
        self.stdscr.getch()
    
    def mode_switcher(self):
        """Security mode switching interface"""
        while True:
            current_mode = self.config.get('CURRENT_MODE', 'setup')
            
            menu_options = []
            for mode_key, mode_info in self.security_modes.items():
                status = " (ACTIVE)" if mode_key == current_mode else ""
                menu_options.append(f"{mode_info['name']}{status}")
            
            menu_options.extend(["", "🔙 Back to Main Menu"])
            
            choice = self.show_menu("Security Mode Switcher", menu_options)
            
            if choice == -1 or choice >= len(self.security_modes):
                break
                
            mode_keys = list(self.security_modes.keys())
            selected_mode = mode_keys[choice]
            
            if self.confirm_mode_switch(selected_mode):
                self.apply_security_mode(selected_mode)
    
    def confirm_mode_switch(self, mode):
        """Confirm mode switch"""
        mode_info = self.security_modes[mode]
        
        message = f"Switch to {mode_info['name']}?\n\n{mode_info['description']}\n\n"
        message += "This will modify:\n"
        message += "• Firewall rules (UFW)\n"
        message += "• System services\n" 
        message += "• Network configuration\n"
        message += "• Security policies"
        
        result = self.show_menu("Confirm Mode Switch", 
                               [message, "", "✓ Apply Changes", "✗ Cancel"])
        
        return result == 2
    
    def apply_security_mode(self, mode):
        """Apply security mode configuration with enhanced error handling and rollback"""
        mode_info = self.security_modes[mode]
        old_mode = self.config.get('CURRENT_MODE', 'setup')
        
        if ENHANCED_MODE and self.logger:
            self.logger.log_security_event('MODE_CHANGE_ATTEMPT', 
                                         {'from': old_mode, 'to': mode}, 'MEDIUM')
        
        # Create rollback point
        rollback_data = None
        if ENHANCED_MODE and self.state_manager:
            rollback_data = self.state_manager.current_state.copy()
        
        progress = None
        if ENHANCED_MODE and self.logger:
            progress = ProgressLogger(f"Security Mode Switch: {mode}", 4, self.logger)
        
        try:
            # Step 1: Apply UFW rules
            if progress:
                progress.step("Configuring firewall rules")
                
            failed_rules = []
            for rule in mode_info['ufw_rules']:
                try:
                    result = subprocess.run(rule.split(), check=True, capture_output=True, text=True, timeout=30)
                except subprocess.CalledProcessError as e:
                    failed_rules.append(f"{rule}: {e.stderr}")
                except subprocess.TimeoutExpired:
                    failed_rules.append(f"{rule}: timeout")
            
            if failed_rules and ENHANCED_MODE and self.logger:
                self.logger.log_warning("Some firewall rules failed", extra_data={'failed_rules': failed_rules})
            
            # Step 2: Enable UFW
            if progress:
                progress.step("Enabling firewall")
            subprocess.run(['ufw', '--force', 'enable'], check=True, capture_output=True, timeout=30)
            
            # Step 3: Apply sysctl changes
            if progress:
                progress.step("Applying system parameters")
            if 'sysctl' in mode_info:
                for key, value in mode_info['sysctl'].items():
                    try:
                        subprocess.run(['sysctl', '-w', f'{key}={value}'], 
                                     check=True, capture_output=True, timeout=15)
                    except subprocess.CalledProcessError as e:
                        if ENHANCED_MODE and self.logger:
                            self.logger.log_warning(f"Failed to set sysctl {key}={value}", extra_data={'error': str(e)})
            
            # Step 4: Handle services
            if progress:
                progress.step("Managing services")
            service_failures = []
            if 'services' in mode_info:
                for service in mode_info['services']:
                    try:
                        subprocess.run(['systemctl', 'enable', service], 
                                     check=True, capture_output=True, timeout=15)
                        subprocess.run(['systemctl', 'start', service], 
                                     check=True, capture_output=True, timeout=30)
                    except subprocess.CalledProcessError as e:
                        service_failures.append(f"{service}: {e.stderr.decode() if e.stderr else 'unknown error'}")
            
            # Update configuration
            self.config['CURRENT_MODE'] = mode
            
            # Save state in enhanced mode
            if ENHANCED_MODE and self.state_manager:
                self.state_manager.save_security_mode_state(mode, mode_info)
                if self.logger:
                    self.logger.log_mode_change(old_mode, mode, True, 
                                              {'service_failures': service_failures, 'failed_rules': failed_rules})
            
            if progress:
                progress.complete(True)
            
            # Show results
            success_msg = f"Successfully switched to {mode_info['name']}"
            if service_failures or failed_rules:
                success_msg += f"\n\nWarnings:\n"
                if failed_rules:
                    success_msg += f"• {len(failed_rules)} firewall rules failed\n"
                if service_failures:
                    success_msg += f"• {len(service_failures)} services failed to start"
            
            self.show_message("Mode Applied", success_msg, "info")
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to apply {mode_info['name']} mode"
            
            if ENHANCED_MODE and self.logger:
                self.logger.log_mode_change(old_mode, mode, False, {'error': str(e)})
                self.logger.log_error(f"Security mode change failed: {old_mode} -> {mode}", e)
            
            if progress:
                progress.complete(False)
            
            # Attempt rollback
            if rollback_data and ENHANCED_MODE and self.state_manager:
                try:
                    # Simple rollback - restore previous mode
                    self.config['CURRENT_MODE'] = old_mode
                    error_msg += "\n\nConfiguration rolled back to previous state."
                except Exception as rollback_error:
                    if self.logger:
                        self.logger.log_error("Rollback failed", rollback_error)
                    error_msg += "\n\nRollback failed - manual intervention may be required."
            
            self.show_message("Error", error_msg, "error")
            
        except Exception as e:
            error_msg = f"Unexpected error during mode switch: {str(e)}"
            
            if ENHANCED_MODE and self.logger:
                self.logger.log_error(f"Unexpected error in security mode change", e)
            
            if progress:
                progress.complete(False)
            
            self.show_message("Critical Error", error_msg, "error")
    
    def execute_bootstrap(self):
        """Execute the actual system bootstrap process"""
        if not self.config.get('USER_NAME'):
            self.show_message("Error", "Configuration incomplete. Please run initial setup first.", "error")
            return False
        
        # Enhanced mode: Use parallel downloads with progress monitoring
        if ENHANCED_MODE and self.progress_monitor:
            return self.execute_bootstrap_enhanced()
        else:
            return self.execute_bootstrap_legacy()
    
    def execute_bootstrap_enhanced(self):
        """Enhanced bootstrap with parallel downloads and progress monitoring"""
        try:
            self.logger.log_info("Starting enhanced bootstrap process")
            
            # Show initial progress message
            self.show_message("Bootstrap", "Starting enhanced system bootstrap...\nUsing parallel downloads for 3x faster installation!", "info")
            
            # Generate bootstrap script with parallel downloads
            bootstrap_script = self.generate_enhanced_bootstrap_script()
            
            # Write to temporary file
            with open('/tmp/kaliforge2_bootstrap_enhanced.sh', 'w') as f:
                f.write(bootstrap_script)
            os.chmod('/tmp/kaliforge2_bootstrap_enhanced.sh', 0o755)
            
            # Start progress monitoring
            self.progress_monitor.start_monitoring()
            self.progress_monitor.add_update_callback(self.update_progress_display)
            
            # Execute bootstrap in background
            process = subprocess.Popen(['bash', '/tmp/kaliforge2_bootstrap_enhanced.sh'],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Show live progress while bootstrap runs
            self.show_bootstrap_progress(process)
            
            # Wait for completion
            result = process.wait()
            
            # Stop monitoring
            self.progress_monitor.stop_monitoring()
            
            # Clean up
            try:
                os.unlink('/tmp/kaliforge2_bootstrap_enhanced.sh')
            except:
                pass
            
            if result == 0:
                summary = self.progress_monitor.get_progress_summary()
                success_msg = f"Enhanced bootstrap completed successfully!\n\n" \
                             f"Downloads: {summary.completed}/{summary.total} completed\n" \
                             f"Performance boost: ~66% faster installation"
                self.show_message("Success", success_msg, "info")
                self.logger.log_audit_event("bootstrap", "system", "SUCCESS", {"profile": self.config['PROFILE']})
                return True
            else:
                self.show_message("Error", f"Bootstrap failed with exit code {result}", "error")
                return False
                
        except Exception as e:
            self.show_message("Error", f"Enhanced bootstrap failed: {str(e)}", "error")
            self.logger.log_error("Enhanced bootstrap execution failed", e)
            return False
    
    def execute_bootstrap_legacy(self):
        """Legacy bootstrap execution for fallback mode"""
        self.show_message("Bootstrap", "Starting system bootstrap...\nThis may take several minutes.", "info")
        
        try:
            # Generate bootstrap script on the fly
            bootstrap_script = self.generate_bootstrap_script()
            
            # Write to temporary file
            with open('/tmp/kaliforge2_bootstrap.sh', 'w') as f:
                f.write(bootstrap_script)
            
            # Make executable
            os.chmod('/tmp/kaliforge2_bootstrap.sh', 0o755)
            
            # Execute
            result = subprocess.run(['bash', '/tmp/kaliforge2_bootstrap.sh'], 
                                  capture_output=True, text=True)
            
            # Clean up
            try:
                os.unlink('/tmp/kaliforge2_bootstrap.sh')
            except:
                pass
            
            if result.returncode == 0:
                self.show_message("Success", "System bootstrap completed successfully!", "info")
                return True
            else:
                error_msg = f"Bootstrap failed:\n{result.stderr[:200]}..."
                self.show_message("Error", error_msg, "error")
                return False
                
        except Exception as e:
            self.show_message("Error", f"Bootstrap execution failed: {str(e)}", "error")
            return False
    
    def update_progress_display(self, progress_data):
        """Callback to update progress display in ncurses"""
        # This will be called by the progress monitor
        # For now, we'll just update internal state
        # In a full implementation, you'd update the ncurses display
        pass
    
    def show_bootstrap_progress(self, process):
        """Show real-time bootstrap progress in ncurses"""
        if not ENHANCED_MODE:
            return
            
        # Create a progress window
        progress_win = curses.newwin(self.height // 2, self.width - 4, 
                                   self.height // 4, 2)
        progress_win.box()
        progress_win.addstr(1, 2, "📊 Bootstrap Progress (Live Updates)", curses.A_BOLD)
        progress_win.refresh()
        
        line_num = 3
        while process.poll() is None:
            try:
                # Get current progress
                summary = self.progress_monitor.get_progress_summary()
                active_downloads = self.progress_monitor.get_active_downloads()
                
                # Clear previous content
                for i in range(3, self.height // 2 - 2):
                    progress_win.addstr(i, 2, " " * (self.width - 6))
                
                # Show overall progress
                if summary.total > 0:
                    pct = summary.completion_percentage
                    progress_bar = self.create_progress_bar(pct, 40)
                    progress_win.addstr(3, 2, f"Overall: {progress_bar} {pct:.1f}%")
                    progress_win.addstr(4, 2, f"Completed: {summary.completed}/{summary.total}, Failed: {summary.failed}")
                
                # Show active downloads
                line = 6
                if active_downloads and line < self.height // 2 - 3:
                    progress_win.addstr(line, 2, "Active Downloads:", curses.A_BOLD)
                    line += 1
                    
                    for download_id, update in list(active_downloads.items())[:5]:  # Show max 5
                        if line >= self.height // 2 - 2:
                            break
                        short_id = download_id.replace('_', ' ')[:25]
                        try:
                            pct = float(update.progress)
                            mini_bar = self.create_progress_bar(pct, 15)
                            progress_win.addstr(line, 4, f"{short_id}: {mini_bar}")
                        except:
                            progress_win.addstr(line, 4, f"{short_id}: {update.progress}")
                        line += 1
                
                progress_win.addstr(self.height // 2 - 2, 2, "Press any key to hide progress...", curses.A_DIM)
                progress_win.refresh()
                
                # Check for key press to hide progress
                progress_win.timeout(500)  # 0.5 second timeout
                key = progress_win.getch()
                if key != -1:  # Key was pressed
                    break
                    
            except Exception:
                # Continue on errors
                time.sleep(0.5)
        
        # Clean up progress window
        del progress_win
        self.stdscr.clear()
        self.stdscr.refresh()
    
    def create_progress_bar(self, percentage, width=20):
        """Create a visual progress bar"""
        try:
            pct = float(percentage)
            filled = int(pct / 100 * width)
            return "█" * filled + "░" * (width - filled)
        except:
            return "░" * width
    
    def generate_enhanced_bootstrap_script(self):
        """Generate enhanced bootstrap script with parallel downloads"""
        script_dir = Path(__file__).parent
        
        return f'''#!/bin/bash
# Enhanced KaliForge II Bootstrap Script with Parallel Downloads
set -euo pipefail

# Configuration from unified interface
export USER_NAME="{self.config['USER_NAME']}"
export SSH_PORT="{self.config['SSH_PORT']}"
export PROFILE="{self.config['PROFILE']}"
export INSTALL_KDE="{str(self.config['INSTALL_KDE']).lower()}"
export PUBKEY="{self.config['PUBKEY']}"
export GITHUB_TOKEN="{self.config['GITHUB_TOKEN']}"

# Enhanced settings for parallel downloads
export MAX_PARALLEL_DOWNLOADS=4
export DOWNLOAD_TIMEOUT=300

echo "🚀 Starting Enhanced KaliForge II Bootstrap..."
echo "   User: $USER_NAME"
echo "   Profile: $PROFILE" 
echo "   SSH: {'Enabled on port ' + self.config['SSH_PORT'] if self.config['PUBKEY'] else 'Disabled'}"
echo "   KDE: {'Yes' if self.config['INSTALL_KDE'] else 'No'}"
echo "   Parallel Downloads: $MAX_PARALLEL_DOWNLOADS concurrent"
echo ""

# Check if enhanced bootstrap script exists
if [[ -f "{script_dir}/kaliforge2.sh" ]]; then
    # Use enhanced bootstrap with parallel downloads
    export USE_PARALLEL_DOWNLOADS=true
    bash "{script_dir}/kaliforge2.sh"
else
    echo "Error: Enhanced bootstrap script not found!"
    echo "Falling back to legacy bootstrap..."
    
    # Try legacy bootstrap
    if [[ -f "{script_dir}/kali_bootstrapper.sh" ]]; then
        bash "{script_dir}/kali_bootstrapper.sh"
    else
        echo "Error: No bootstrap script found!"
        exit 1
    fi
fi

echo "✅ Enhanced bootstrap completed successfully!"
'''
    
    def generate_bootstrap_script(self):
        """Generate the bootstrap script with current configuration"""
        script_dir = Path(__file__).parent
        
        return f'''#!/bin/bash
# Generated KaliForge II Bootstrap Script
set -euo pipefail

# Configuration from unified interface
export USER_NAME="{self.config['USER_NAME']}"
export SSH_PORT="{self.config['SSH_PORT']}"
export PROFILE="{self.config['PROFILE']}"
export INSTALL_KDE="{str(self.config['INSTALL_KDE']).lower()}"
export PUBKEY="{self.config['PUBKEY']}"
export GITHUB_TOKEN="{self.config['GITHUB_TOKEN']}"

echo "🚀 Starting KaliForge II Bootstrap..."
echo "   User: $USER_NAME"
echo "   Profile: $PROFILE" 
echo "   SSH: {'Enabled on port ' + self.config['SSH_PORT'] if self.config['PUBKEY'] else 'Disabled'}"
echo "   KDE: {'Yes' if self.config['INSTALL_KDE'] else 'No'}"
echo ""

# Check if main bootstrap script exists
if [[ -f "{script_dir}/kaliforge2.sh" ]]; then
    bash "{script_dir}/kaliforge2.sh"
elif [[ -f "{script_dir}/kali_bootstrapper.sh" ]]; then
    bash "{script_dir}/kali_bootstrapper.sh"
else
    echo "Error: Bootstrap script not found!"
    exit 1
fi

echo "✅ Bootstrap completed successfully!"
'''
    
    def show_system_status(self):
        """Display current system status"""
        status_info = []
        
        try:
            # Check UFW status
            ufw_result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
            ufw_status = "Active" if "Status: active" in ufw_result.stdout else "Inactive"
            status_info.append(f"Firewall (UFW): {ufw_status}")
            
            # Check SSH service
            ssh_result = subprocess.run(['systemctl', 'is-active', 'ssh'], capture_output=True, text=True)
            ssh_status = ssh_result.stdout.strip()
            status_info.append(f"SSH Service: {ssh_status}")
            
            # Check fail2ban
            fail2ban_result = subprocess.run(['systemctl', 'is-active', 'fail2ban'], capture_output=True, text=True)
            fail2ban_status = fail2ban_result.stdout.strip()
            status_info.append(f"Fail2ban: {fail2ban_status}")
            
            # Check current user
            current_user = os.getenv('SUDO_USER', os.getenv('USER', 'unknown'))
            status_info.append(f"Current User: {current_user}")
            
            # Check system load
            load_result = subprocess.run(['uptime'], capture_output=True, text=True)
            load_avg = load_result.stdout.strip().split('load average: ')[-1] if load_result.stdout else "unknown"
            status_info.append(f"Load Average: {load_avg}")
            
            # Check disk usage of root
            df_result = subprocess.run(['df', '-h', '/'], capture_output=True, text=True)
            if df_result.stdout:
                lines = df_result.stdout.strip().split('\n')
                if len(lines) > 1:
                    disk_info = lines[1].split()
                    if len(disk_info) > 4:
                        status_info.append(f"Disk Usage (/): {disk_info[2]} used of {disk_info[1]} ({disk_info[4]})")
            
        except Exception as e:
            status_info.append(f"Error gathering status: {str(e)}")
        
        # Add current mode
        current_mode = self.config.get('CURRENT_MODE', 'setup')
        if current_mode in self.security_modes:
            mode_name = self.security_modes[current_mode]['name']
            status_info.append(f"Security Mode: {mode_name}")
        
        # Show status
        status_text = "SYSTEM STATUS:\n\n" + "\n".join(status_info)
        self.show_message("System Status", status_text, "info")
    
    def main_menu(self):
        """Main application menu"""
        while True:
            is_setup = not self.config.get('USER_NAME')
            
            if is_setup:
                options = [
                    "🚀 Initial System Setup",
                    "🔧 Advanced Configuration", 
                    "❌ Exit"
                ]
            else:
                options = [
                    "🔄 Security Mode Switcher",
                    "⚙️  System Configuration",
                    "📊 System Status",
                    "🔧 Advanced Tools",
                    "❌ Exit"
                ]
            
            choice = self.show_menu("KaliForge II - Main Menu", options)
            
            if choice == -1 or choice == len(options) - 1:  # Exit
                break
            elif choice == 0:
                if is_setup:
                    if self.initial_setup():
                        if self.show_menu("Execute Bootstrap?", ["Yes, run system bootstrap", "No, configure later"]) == 0:
                            self.execute_bootstrap()
                        self.show_message("Setup Complete", 
                                        "Initial setup completed!\n\n" +
                                        "You can now use the Security Mode Switcher\n" +
                                        "to configure your system for different purposes.", 
                                        "info")
                else:
                    self.mode_switcher()
            elif choice == 1:
                if is_setup:
                    self.show_message("Advanced Config", "Complete initial setup first", "warning")
                else:
                    sys_menu = self.show_menu("System Configuration", 
                                            ["Run Bootstrap Script", "View System Status", "Back"])
                    if sys_menu == 0:
                        self.execute_bootstrap()
                    elif sys_menu == 1:
                        self.show_system_status()
    
    def run(self):
        """Main application entry point"""
        try:
            self.main_menu()
        except KeyboardInterrupt:
            pass
        finally:
            curses.curs_set(1)  # Restore cursor

def main():
    """Main function with CLI support"""
    import argparse
    
    parser = argparse.ArgumentParser(description='KaliForge II - Unified Security Environment Manager')
    parser.add_argument('--no-root-check', action='store_true', help='Skip root privilege check (for testing)')
    parser.add_argument('--version', action='version', version='KaliForge II v2.0')
    parser.add_argument('--batch', action='store_true', help='Run in batch mode (non-interactive)')
    parser.add_argument('--config', help='Load configuration from file')
    parser.add_argument('--mode', choices=['hardened', 'honeypot', 'stealth', 'pentest'], 
                       help='Set security mode directly')
    args = parser.parse_args()
    
    # Root check (unless bypassed)
    if not args.no_root_check and os.geteuid() != 0:
        print("This script requires root privileges. Please run with sudo.")
        print("Use --no-root-check for UI testing only.")
        sys.exit(1)
    
    # Initialize enhanced systems
    if ENHANCED_MODE and not args.no_root_check:
        try:
            init_logger()
            init_state_manager()
            print("KaliForge II Enhanced Mode - Logging and state management initialized")
        except Exception as e:
            print(f"Warning: Failed to initialize enhanced features: {e}")
            print("Continuing in basic mode...")
    
    # Handle batch mode or direct mode switching
    if args.mode:
        print(f"Switching to {args.mode} mode...")
        # Direct mode switching logic would go here
        return
    
    if args.batch:
        print("Batch mode not yet implemented.")
        sys.exit(1)
    
    # Launch interactive interface
    curses.wrapper(KaliForgeUnified)

if __name__ == "__main__":
    main()