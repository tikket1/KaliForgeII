#!/usr/bin/env python3
"""
KaliForge II - ncurses-based TUI
Enhanced interface with proper ASCII art display and scrolling
"""

import curses
import os
import sys
import subprocess
import json
from pathlib import Path

class KaliForgeUI:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.height, self.width = stdscr.getmaxyx()
        self.config = {
            'USER_NAME': 'tikket',
            'SSH_PORT': '2222', 
            'PROFILE': 'standard',
            'INSTALL_KDE': True,
            'PUBKEY': '',
            'GITHUB_TOKEN': ''
        }
        
        # Initialize color pairs
        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)      # Headers
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)     # Success
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)    # Warning
        curses.init_pair(4, curses.COLOR_RED, curses.COLOR_BLACK)       # Error
        curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)   # Highlight
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLUE)      # Selected
        
        # Disable cursor
        curses.curs_set(0)
        
        # Load ASCII art
        self.ascii_art = self.load_ascii_art()
        
    def load_ascii_art(self):
        """Load the ASCII art from file"""
        # Try to load the clean ASCII art file first
        clean_art_file = Path(__file__).parent / "kaliforge2_ascii_clean.txt"
        if clean_art_file.exists():
            try:
                with open(clean_art_file, 'r', encoding='utf-8') as f:
                    return f.read().splitlines()
            except Exception:
                pass
        
        # Try to load converted RTF file
        art_file = Path(__file__).parent / "ascii_kaliforge.txt"
        if art_file.exists():
            try:
                # Convert RTF to text if needed
                if not Path("/tmp/ascii_kaliforge.txt").exists():
                    subprocess.run([
                        "textutil", "-convert", "txt", 
                        str(Path(__file__).parent / "ascii_kaliforge.rtf"),
                        "-output", "/tmp/ascii_kaliforge.txt"
                    ], check=False, capture_output=True)
                
                with open("/tmp/ascii_kaliforge.txt", 'r', encoding='utf-8') as f:
                    return f.read().splitlines()
            except Exception:
                pass
        
        # Fallback ASCII art if file not found
        return [
            "╔══════════════════════════════════════════════════════════════╗",
            "║  ██╗  ██╗ █████╗ ██╗     ██╗███████╗ ██████╗  ██████╗  ██╗██╗║",
            "║  ██║ ██╔╝██╔══██╗██║     ██║██╔════╝██╔═══██╗██╔══██╗ ██║██║║",
            "║  █████╔╝ ███████║██║     ██║█████╗  ██║   ██║██████╔╝ ██║██║║",
            "║  ██╔═██╗ ██╔══██║██║     ██║██╔══╝  ██║   ██║██╔══██╗ ██║██║║",
            "║  ██║  ██╗██║  ██║███████╗██║██║     ╚██████╔╝██║  ██║ ██║██║║",
            "║  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═╝╚═╝║",
            "║                                                              ║",
            "║           🚀 Next-Generation Kali Environment 🚀             ║",
            "║                                                              ║",
            "╚══════════════════════════════════════════════════════════════╝"
        ]
    
    def draw_box(self, y, x, height, width, title=""):
        """Draw a box with optional title"""
        # Draw corners and edges
        self.stdscr.addch(y, x, curses.ACS_ULCORNER)
        self.stdscr.addch(y, x + width - 1, curses.ACS_URCORNER)
        self.stdscr.addch(y + height - 1, x, curses.ACS_LLCORNER)
        self.stdscr.addch(y + height - 1, x + width - 1, curses.ACS_LRCORNER)
        
        # Draw horizontal lines
        for i in range(1, width - 1):
            self.stdscr.addch(y, x + i, curses.ACS_HLINE)
            self.stdscr.addch(y + height - 1, x + i, curses.ACS_HLINE)
        
        # Draw vertical lines
        for i in range(1, height - 1):
            self.stdscr.addch(y + i, x, curses.ACS_VLINE)
            self.stdscr.addch(y + i, x + width - 1, curses.ACS_VLINE)
        
        # Add title if provided
        if title:
            title_text = f" {title} "
            title_x = x + (width - len(title_text)) // 2
            self.stdscr.addstr(y, title_x, title_text, curses.color_pair(1) | curses.A_BOLD)

    def display_ascii_art_scrollable(self):
        """Display ASCII art with scrolling capability"""
        self.stdscr.clear()
        
        art_height = len(self.ascii_art)
        max_width = max(len(line) for line in self.ascii_art) if self.ascii_art else 0
        
        # Create a scrollable window for the ASCII art
        art_win_height = min(self.height - 6, art_height + 2)
        art_win_width = min(self.width - 4, max_width + 4)
        
        # Center the window
        start_y = (self.height - art_win_height) // 2
        start_x = (self.width - art_win_width) // 2
        
        # Create the ASCII art display window
        art_win = curses.newwin(art_win_height, art_win_width, start_y, start_x)
        art_win.box()
        art_win.addstr(0, 2, " KaliForge II ", curses.color_pair(1) | curses.A_BOLD)
        
        # Display ASCII art (scaled to fit if needed)
        display_lines = self.ascii_art[:art_win_height - 2]  # Leave room for border
        
        for i, line in enumerate(display_lines):
            if i < art_win_height - 2:
                # Truncate line if too wide, or center it
                display_line = line[:art_win_width - 4] if len(line) > art_win_width - 4 else line
                line_x = max(2, (art_win_width - len(display_line)) // 2)
                try:
                    art_win.addstr(i + 1, line_x, display_line, curses.color_pair(5))
                except curses.error:
                    pass  # Skip lines that don't fit
        
        # Add instructions
        instructions = "Press any key to continue..."
        instr_y = start_y + art_win_height + 1
        instr_x = (self.width - len(instructions)) // 2
        self.stdscr.addstr(instr_y, instr_x, instructions, curses.color_pair(3) | curses.A_BLINK)
        
        art_win.refresh()
        self.stdscr.refresh()
        self.stdscr.getch()
        
        art_win.clear()
        del art_win

    def show_menu(self, title, options, selected=0):
        """Display a menu and return selected option"""
        menu_height = len(options) + 4
        menu_width = max(len(option) for option in options) + 8
        menu_width = max(menu_width, len(title) + 4)
        
        # Center the menu
        start_y = (self.height - menu_height) // 2
        start_x = (self.width - menu_width) // 2
        
        while True:
            self.stdscr.clear()
            self.draw_box(start_y, start_x, menu_height, menu_width, title)
            
            # Display options
            for i, option in enumerate(options):
                y = start_y + 2 + i
                x = start_x + 2
                
                if i == selected:
                    self.stdscr.addstr(y, x, f"> {option}", curses.color_pair(6) | curses.A_BOLD)
                else:
                    self.stdscr.addstr(y, x, f"  {option}", curses.color_pair(1))
            
            self.stdscr.refresh()
            
            # Handle input
            key = self.stdscr.getch()
            
            if key == curses.KEY_UP and selected > 0:
                selected -= 1
            elif key == curses.KEY_DOWN and selected < len(options) - 1:
                selected += 1
            elif key in [curses.KEY_ENTER, ord('\n'), ord('\r')]:
                return selected
            elif key == 27:  # ESC key
                return -1

    def get_input(self, prompt, default=""):
        """Get text input from user"""
        input_height = 5
        input_width = min(60, self.width - 4)
        
        start_y = (self.height - input_height) // 2
        start_x = (self.width - input_width) // 2
        
        # Enable cursor for input
        curses.curs_set(1)
        
        self.stdscr.clear()
        self.draw_box(start_y, start_x, input_height, input_width, "Input")
        
        # Display prompt
        self.stdscr.addstr(start_y + 1, start_x + 2, prompt, curses.color_pair(1))
        
        # Create input field
        input_y = start_y + 2
        input_x = start_x + 2
        input_field_width = input_width - 6
        
        # Show default value
        current_input = default
        self.stdscr.addstr(input_y, input_x, current_input[:input_field_width], curses.color_pair(6))
        self.stdscr.addstr(start_y + 3, start_x + 2, "Press ENTER to confirm, ESC to cancel", curses.color_pair(3))
        
        self.stdscr.move(input_y, input_x + len(current_input))
        self.stdscr.refresh()
        
        while True:
            key = self.stdscr.getch()
            
            if key in [curses.KEY_ENTER, ord('\n'), ord('\r')]:
                curses.curs_set(0)
                return current_input
            elif key == 27:  # ESC
                curses.curs_set(0)
                return default
            elif key in [curses.KEY_BACKSPACE, ord('\b'), 127]:
                if current_input:
                    current_input = current_input[:-1]
            elif 32 <= key <= 126:  # Printable characters
                if len(current_input) < input_field_width:
                    current_input += chr(key)
            
            # Redraw input field
            self.stdscr.addstr(input_y, input_x, " " * input_field_width)
            self.stdscr.addstr(input_y, input_x, current_input[:input_field_width], curses.color_pair(6))
            self.stdscr.move(input_y, input_x + len(current_input))
            self.stdscr.refresh()

    def show_profile_details(self, profile):
        """Show detailed profile information"""
        profiles = {
            'minimal': {
                'title': 'Minimal Profile',
                'description': 'Basic reconnaissance tools',
                'tools': ['nmap', 'netcat', 'curl', 'wget', 'jq'],
                'use_case': 'Basic network testing, lightweight VMs'
            },
            'webapp': {
                'title': 'Web Application Profile', 
                'description': 'Web application security testing',
                'tools': ['gobuster', 'sqlmap', 'BurpSuite', 'nuclei', 'ffuf', 'feroxbuster'],
                'use_case': 'Web app pentesting, bug bounties'
            },
            'internal': {
                'title': 'Internal Network Profile',
                'description': 'Internal network penetration testing',
                'tools': ['crackmapexec', 'impacket', 'BloodHound', 'responder', 'enum4linux'],
                'use_case': 'Corporate network assessments'
            },
            'cloud': {
                'title': 'Cloud Security Profile',
                'description': 'Cloud security testing tools', 
                'tools': ['awscli', 'kubectl', 'terraform', 'docker', 'azure-cli'],
                'use_case': 'Cloud penetration testing'
            },
            'standard': {
                'title': 'Standard Profile',
                'description': 'Balanced toolkit for general pentesting',
                'tools': ['Network scanning', 'Web testing', 'Basic exploitation', 'Docker support'],
                'use_case': 'General penetration testing'
            },
            'heavy': {
                'title': 'Heavy Profile',
                'description': 'Full arsenal of security tools',
                'tools': ['Everything from standard', 'Metasploit', 'BloodHound', 'Password cracking'],
                'use_case': 'Comprehensive security assessments'
            }
        }
        
        profile_info = profiles.get(profile, profiles['standard'])
        
        details_height = 15
        details_width = 70
        
        start_y = (self.height - details_height) // 2
        start_x = (self.width - details_width) // 2
        
        self.stdscr.clear()
        self.draw_box(start_y, start_x, details_height, details_width, profile_info['title'])
        
        y_offset = start_y + 2
        
        # Description
        self.stdscr.addstr(y_offset, start_x + 2, "Description:", curses.color_pair(1) | curses.A_BOLD)
        self.stdscr.addstr(y_offset + 1, start_x + 2, profile_info['description'], curses.color_pair(2))
        
        # Tools
        self.stdscr.addstr(y_offset + 3, start_x + 2, "Key Tools:", curses.color_pair(1) | curses.A_BOLD)
        for i, tool in enumerate(profile_info['tools'][:8]):  # Limit to 8 tools for space
            self.stdscr.addstr(y_offset + 4 + i, start_x + 4, f"• {tool}", curses.color_pair(5))
        
        # Use case
        self.stdscr.addstr(y_offset + 12, start_x + 2, "Ideal for:", curses.color_pair(1) | curses.A_BOLD)
        self.stdscr.addstr(y_offset + 13, start_x + 2, profile_info['use_case'], curses.color_pair(2))
        
        self.stdscr.addstr(self.height - 2, 2, "Press any key to continue...", curses.color_pair(3))
        self.stdscr.refresh()
        self.stdscr.getch()

    def main_flow(self):
        """Main TUI flow"""
        # Show ASCII art welcome
        self.display_ascii_art_scrollable()
        
        while True:
            # Profile selection
            profiles = ['minimal', 'webapp', 'internal', 'cloud', 'standard', 'heavy']
            profile_idx = self.show_menu("Select KaliForge II Profile", profiles)
            
            if profile_idx == -1:
                return False
            
            self.config['PROFILE'] = profiles[profile_idx]
            
            # Show profile details
            self.show_profile_details(self.config['PROFILE'])
            
            # Configuration menu
            config_options = [
                'Configure User Settings',
                'Configure SSH Settings', 
                'Configure Desktop Environment',
                'Configure GitHub Integration',
                'View Configuration Summary',
                'Start Installation',
                'Save Configuration & Exit',
                'Cancel'
            ]
            
            while True:
                choice = self.show_menu(f"KaliForge II - Profile: {self.config['PROFILE']}", config_options)
                
                if choice == -1 or choice == 7:  # Cancel
                    return False
                elif choice == 0:  # User settings
                    self.config['USER_NAME'] = self.get_input("Username:", self.config['USER_NAME'])
                elif choice == 1:  # SSH settings
                    self.config['SSH_PORT'] = self.get_input("SSH Port:", self.config['SSH_PORT'])
                    self.config['PUBKEY'] = self.get_input("SSH Public Key:", self.config['PUBKEY'])
                elif choice == 2:  # Desktop
                    desktop_choice = self.show_menu("Install KDE Desktop?", ['Yes', 'No'])
                    self.config['INSTALL_KDE'] = desktop_choice == 0
                elif choice == 3:  # GitHub
                    self.config['GITHUB_TOKEN'] = self.get_input("GitHub Token (optional):", self.config['GITHUB_TOKEN'])
                elif choice == 4:  # View config
                    self.show_config_summary()
                elif choice == 5:  # Install
                    return self.confirm_installation()
                elif choice == 6:  # Save & exit
                    self.save_config()
                    return False

    def show_config_summary(self):
        """Display configuration summary"""
        summary_height = 12
        summary_width = 60
        
        start_y = (self.height - summary_height) // 2
        start_x = (self.width - summary_width) // 2
        
        self.stdscr.clear()
        self.draw_box(start_y, start_x, summary_height, summary_width, "Configuration Summary")
        
        y_offset = start_y + 2
        
        self.stdscr.addstr(y_offset, start_x + 2, f"Profile: {self.config['PROFILE']}", curses.color_pair(2))
        self.stdscr.addstr(y_offset + 1, start_x + 2, f"User: {self.config['USER_NAME']}", curses.color_pair(2))
        self.stdscr.addstr(y_offset + 2, start_x + 2, f"SSH Port: {self.config['SSH_PORT']}", curses.color_pair(2))
        
        ssh_status = "ENABLED" if self.config['PUBKEY'] else "DISABLED"
        self.stdscr.addstr(y_offset + 3, start_x + 2, f"SSH: {ssh_status}", curses.color_pair(2))
        
        kde_status = "Yes" if self.config['INSTALL_KDE'] else "No"
        self.stdscr.addstr(y_offset + 4, start_x + 2, f"KDE Desktop: {kde_status}", curses.color_pair(2))
        
        github_status = "Configured" if self.config['GITHUB_TOKEN'] else "Not configured"
        self.stdscr.addstr(y_offset + 5, start_x + 2, f"GitHub: {github_status}", curses.color_pair(2))
        
        self.stdscr.addstr(y_offset + 8, start_x + 2, "Press any key to continue...", curses.color_pair(3))
        self.stdscr.refresh()
        self.stdscr.getch()

    def confirm_installation(self):
        """Confirm installation and launch"""
        choice = self.show_menu("Ready to Install KaliForge II?", ['Start Installation', 'Back to Configuration', 'Cancel'])
        
        if choice == 0:
            self.save_config()
            return True
        elif choice == 1:
            return False  # Go back to config
        else:
            return False  # Cancel

    def save_config(self):
        """Save configuration to file"""
        config_file = "/tmp/kaliforge2.conf"
        with open(config_file, 'w') as f:
            f.write(f'export USER_NAME="{self.config["USER_NAME"]}"\n')
            f.write(f'export SSH_PORT="{self.config["SSH_PORT"]}"\n')
            f.write(f'export PROFILE="{self.config["PROFILE"]}"\n')
            f.write(f'export INSTALL_KDE="{str(self.config["INSTALL_KDE"]).lower()}"\n')
            f.write(f'export PUBKEY="{self.config["PUBKEY"]}"\n')
            f.write(f'export GITHUB_TOKEN="{self.config["GITHUB_TOKEN"]}"\n')

def main(stdscr):
    try:
        ui = KaliForgeUI(stdscr)
        should_install = ui.main_flow()
        
        if should_install:
            stdscr.clear()
            stdscr.addstr(0, 0, "Launching KaliForge II installation...", curses.color_pair(2) | curses.A_BOLD)
            stdscr.refresh()
            curses.endwin()
            
            # Launch the installation script
            script_dir = Path(__file__).parent
            install_script = script_dir / "kaliforge2.sh"
            
            if install_script.exists():
                os.system(f"bash {install_script}")
            else:
                print(f"Error: Installation script not found at {install_script}")
                print("Please ensure kaliforge2.sh is in the same directory.")
        else:
            stdscr.clear()
            stdscr.addstr(0, 0, "KaliForge II setup cancelled.", curses.color_pair(3))
            stdscr.refresh()
            stdscr.getch()
            
    except KeyboardInterrupt:
        pass
    except Exception as e:
        curses.endwin()
        print(f"Error: {e}")

if __name__ == "__main__":
    # Check if running as root
    if os.geteuid() != 0:
        print("This script must be run as root (use sudo)")
        sys.exit(1)
    
    # Check for ncurses
    try:
        curses.wrapper(main)
    except ImportError:
        print("Error: Python ncurses module not found.")
        print("Install with: apt-get install python3-curses")
        sys.exit(1)