#!/usr/bin/env python3
"""
KaliForge II UI Test - Safe preview without installation
Shows how the ASCII art and interface will look
"""

import curses
import os
import sys
from pathlib import Path

class UITestPreview:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.height, self.width = stdscr.getmaxyx()
        
        # Initialize colors
        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)      # Headers
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)     # Success
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)    # Warning
        curses.init_pair(4, curses.COLOR_RED, curses.COLOR_BLACK)       # Error
        curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)   # Highlight
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLUE)      # Selected
        
        curses.curs_set(0)  # Hide cursor
        
    def show_terminal_info(self):
        """Show current terminal dimensions and capabilities"""
        self.stdscr.clear()
        
        info_lines = [
            "═══════════════════════════════════════════════",
            "           🖥️  Terminal Information 🖥️",
            "═══════════════════════════════════════════════",
            "",
            f"Terminal Size: {self.width} x {self.height}",
            f"Colors Available: {curses.COLORS if curses.has_colors() else 'No colors'}",
            f"Color Pairs: {curses.COLOR_PAIRS if curses.has_colors() else 'N/A'}",
            "",
            "Your ASCII Art Dimensions:",
            f"• Width: 949 characters (needs {949} columns)",
            f"• Height: 167 lines (needs {167} rows)",
            "",
            "Fit Analysis:",
            f"• Width fit: {'✅ YES' if self.width >= 949 else '❌ NO - will be scaled/truncated'}",
            f"• Height fit: {'✅ YES' if self.height >= 167 else '❌ NO - will be scaled/truncated'}",
            "",
            "Press any key to continue..."
        ]
        
        start_y = max(0, (self.height - len(info_lines)) // 2)
        
        for i, line in enumerate(info_lines):
            y = start_y + i
            if y < self.height - 1:
                x = max(0, (self.width - len(line)) // 2)
                if "✅" in line:
                    self.stdscr.addstr(y, x, line, curses.color_pair(2))
                elif "❌" in line:
                    self.stdscr.addstr(y, x, line, curses.color_pair(4))
                elif "🖥️" in line:
                    self.stdscr.addstr(y, x, line, curses.color_pair(1) | curses.A_BOLD)
                else:
                    self.stdscr.addstr(y, x, line, curses.color_pair(5))
        
        self.stdscr.refresh()
        self.stdscr.getch()

    def preview_ascii_art(self):
        """Show how the ASCII art will be displayed"""
        self.stdscr.clear()
        
        # Load the actual ASCII art
        ascii_lines = self.load_ascii_art()
        
        if not ascii_lines:
            self.stdscr.addstr(self.height//2, (self.width-20)//2, "ASCII art file not found", curses.color_pair(4))
            self.stdscr.refresh()
            self.stdscr.getch()
            return
        
        # Show preview window
        preview_height = min(self.height - 4, len(ascii_lines) + 2)
        preview_width = min(self.width - 2, 120)  # Reasonable max width
        
        start_y = (self.height - preview_height) // 2
        start_x = (self.width - preview_width) // 2
        
        # Draw border
        try:
            self.stdscr.addstr(start_y - 1, start_x, "┌" + "─" * (preview_width - 2) + "┐", curses.color_pair(1))
            self.stdscr.addstr(start_y + preview_height, start_x, "└" + "─" * (preview_width - 2) + "┘", curses.color_pair(1))
            
            for i in range(preview_height):
                self.stdscr.addstr(start_y + i, start_x, "│", curses.color_pair(1))
                self.stdscr.addstr(start_y + i, start_x + preview_width - 1, "│", curses.color_pair(1))
        except curses.error:
            pass
        
        # Display ASCII art (scaled to fit)
        display_lines = ascii_lines[:preview_height - 2]
        
        for i, line in enumerate(display_lines):
            y = start_y + i + 1
            if y < start_y + preview_height - 1:
                # Truncate or center the line
                display_line = line[:preview_width - 4]
                line_x = start_x + 2
                
                try:
                    self.stdscr.addstr(y, line_x, display_line, curses.color_pair(5))
                except curses.error:
                    pass
        
        # Add status info
        status_y = start_y + preview_height + 2
        status_lines = [
            f"Showing {len(display_lines)} of {len(ascii_lines)} lines",
            f"Original width: {max(len(line) for line in ascii_lines)} chars, showing ~{preview_width-4}",
            "This is how it will appear in the actual TUI",
            "",
            "Press any key to continue..."
        ]
        
        for i, status in enumerate(status_lines):
            try:
                x = (self.width - len(status)) // 2
                self.stdscr.addstr(status_y + i, x, status, curses.color_pair(3))
            except curses.error:
                pass
        
        self.stdscr.refresh()
        self.stdscr.getch()

    def load_ascii_art(self):
        """Load ASCII art from file"""
        # Try to load the clean ASCII art file first
        clean_art_file = Path(__file__).parent / "kaliforge2_ascii_clean.txt"
        if clean_art_file.exists():
            try:
                with open(clean_art_file, 'r', encoding='utf-8') as f:
                    return f.read().splitlines()
            except Exception:
                pass
        
        # Try to load the converted text file
        if Path("/tmp/ascii_kaliforge.txt").exists():
            try:
                with open("/tmp/ascii_kaliforge.txt", 'r', encoding='utf-8') as f:
                    return f.read().splitlines()
            except Exception:
                pass
        
        # Try to convert RTF file
        rtf_file = Path(__file__).parent / "ascii_kaliforge.rtf"
        if rtf_file.exists():
            try:
                import subprocess
                result = subprocess.run([
                    "textutil", "-convert", "txt", str(rtf_file), 
                    "-output", "/tmp/ascii_kaliforge.txt"
                ], check=True, capture_output=True)
                
                with open("/tmp/ascii_kaliforge.txt", 'r', encoding='utf-8') as f:
                    return f.read().splitlines()
            except Exception:
                pass
        
        # Return None if no art found
        return None

    def demo_menu_system(self):
        """Show how the menu system will look"""
        self.stdscr.clear()
        
        # Demo menu
        menu_items = [
            "minimal - Basic tools only",
            "webapp - Web application testing",
            "internal - Internal network testing", 
            "cloud - Cloud security testing",
            "standard - Balanced general toolkit",
            "heavy - Full security arsenal"
        ]
        
        selected = 0
        
        while True:
            self.stdscr.clear()
            
            # Title
            title = "KaliForge II - Profile Selection (DEMO)"
            self.stdscr.addstr(2, (self.width - len(title)) // 2, title, curses.color_pair(1) | curses.A_BOLD)
            
            # Menu box
            menu_height = len(menu_items) + 4
            menu_width = max(len(item) for item in menu_items) + 6
            start_y = (self.height - menu_height) // 2
            start_x = (self.width - menu_width) // 2
            
            # Draw menu border
            try:
                for y in range(start_y, start_y + menu_height):
                    for x in range(start_x, start_x + menu_width):
                        if y == start_y or y == start_y + menu_height - 1:
                            self.stdscr.addch(y, x, "─", curses.color_pair(1))
                        elif x == start_x or x == start_x + menu_width - 1:
                            self.stdscr.addch(y, x, "│", curses.color_pair(1))
                        
                # Corners
                self.stdscr.addch(start_y, start_x, "┌", curses.color_pair(1))
                self.stdscr.addch(start_y, start_x + menu_width - 1, "┐", curses.color_pair(1))
                self.stdscr.addch(start_y + menu_height - 1, start_x, "└", curses.color_pair(1))
                self.stdscr.addch(start_y + menu_height - 1, start_x + menu_width - 1, "┘", curses.color_pair(1))
            except curses.error:
                pass
            
            # Menu items
            for i, item in enumerate(menu_items):
                y = start_y + 2 + i
                x = start_x + 2
                
                if i == selected:
                    try:
                        self.stdscr.addstr(y, x, f"► {item}", curses.color_pair(6) | curses.A_BOLD)
                    except curses.error:
                        pass
                else:
                    try:
                        self.stdscr.addstr(y, x, f"  {item}", curses.color_pair(5))
                    except curses.error:
                        pass
            
            # Instructions
            instructions = [
                "Use ↑↓ arrows to navigate",
                "Press ENTER to select",
                "Press 'q' to exit demo"
            ]
            
            for i, instruction in enumerate(instructions):
                try:
                    x = (self.width - len(instruction)) // 2
                    self.stdscr.addstr(self.height - 4 + i, x, instruction, curses.color_pair(3))
                except curses.error:
                    pass
            
            self.stdscr.refresh()
            
            # Handle input
            key = self.stdscr.getch()
            
            if key == curses.KEY_UP and selected > 0:
                selected -= 1
            elif key == curses.KEY_DOWN and selected < len(menu_items) - 1:
                selected += 1
            elif key in [curses.KEY_ENTER, ord('\n'), ord('\r')]:
                # Show selection
                self.stdscr.addstr(self.height - 1, 0, f"Selected: {menu_items[selected]}", curses.color_pair(2) | curses.A_BOLD)
                self.stdscr.refresh()
                self.stdscr.getch()
                return
            elif key in [ord('q'), ord('Q'), 27]:  # q or ESC
                return

    def run_tests(self):
        """Run all UI tests"""
        tests = [
            ("Terminal Information", self.show_terminal_info),
            ("ASCII Art Preview", self.preview_ascii_art), 
            ("Menu System Demo", self.demo_menu_system)
        ]
        
        for i, (name, test_func) in enumerate(tests):
            self.stdscr.clear()
            
            # Show test menu
            title = f"KaliForge II UI Test Suite ({i+1}/{len(tests)})"
            self.stdscr.addstr(2, (self.width - len(title)) // 2, title, curses.color_pair(1) | curses.A_BOLD)
            
            test_info = f"Next Test: {name}"
            self.stdscr.addstr(4, (self.width - len(test_info)) // 2, test_info, curses.color_pair(2))
            
            instructions = [
                "This will show you how the UI components will look",
                "without actually running any installation code.",
                "",
                "Press ENTER to run test, 'q' to quit"
            ]
            
            start_y = self.height // 2 - 2
            for j, instruction in enumerate(instructions):
                x = (self.width - len(instruction)) // 2
                self.stdscr.addstr(start_y + j, x, instruction, curses.color_pair(5))
            
            self.stdscr.refresh()
            
            key = self.stdscr.getch()
            if key in [ord('q'), ord('Q'), 27]:
                break
            elif key in [curses.KEY_ENTER, ord('\n'), ord('\r')]:
                test_func()

def main(stdscr):
    try:
        preview = UITestPreview(stdscr)
        preview.run_tests()
        
        # Final message
        stdscr.clear()
        final_msg = [
            "UI Test Complete!",
            "",
            "The actual KaliForge II TUI will look similar to what you just saw,",
            "but with full functionality for configuration and installation.",
            "",
            "Press any key to exit..."
        ]
        
        start_y = (stdscr.getmaxyx()[0] - len(final_msg)) // 2
        for i, msg in enumerate(final_msg):
            x = (stdscr.getmaxyx()[1] - len(msg)) // 2
            stdscr.addstr(start_y + i, x, msg, curses.color_pair(2) if i == 0 else curses.color_pair(5))
        
        stdscr.refresh()
        stdscr.getch()
        
    except KeyboardInterrupt:
        pass
    except Exception as e:
        curses.endwin()
        print(f"Test error: {e}")

if __name__ == "__main__":
    try:
        curses.wrapper(main)
    except ImportError:
        print("Error: Python ncurses module not found.")
        print("On macOS: pip3 install windows-curses (if needed)")
        print("On Linux: apt-get install python3-curses")
    except Exception as e:
        print(f"Error running UI test: {e}")