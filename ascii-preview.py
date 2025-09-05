#!/usr/bin/env python3
"""
Simple ASCII Art Preview - Shows how the art will look in terminals
"""

import os
from pathlib import Path

def show_ascii_art():
    """Display the ASCII art with terminal info"""
    
    # Get terminal size
    try:
        columns, lines = os.get_terminal_size()
    except:
        columns, lines = 80, 24  # default fallback
    
    print("=" * min(columns, 80))
    print("🖥️  KALIFORGE II ASCII ART PREVIEW")
    print("=" * min(columns, 80))
    print()
    print(f"Your Terminal: {columns} columns x {lines} lines")
    
    # Load ASCII art
    art_file = Path(__file__).parent / "kaliforge2_ascii_clean.txt"
    if art_file.exists():
        with open(art_file, 'r', encoding='utf-8') as f:
            ascii_lines = f.read().splitlines()
        
        art_width = max(len(line) for line in ascii_lines)
        art_height = len(ascii_lines)
        
        print(f"ASCII Art: {art_width} columns x {art_height} lines")
        print()
        
        # Fit analysis
        width_fit = "✅ FITS" if columns >= art_width else f"❌ TOO WIDE (needs {art_width})"
        height_fit = "✅ FITS" if lines >= art_height else f"❌ TOO TALL (needs {art_height})"
        
        print(f"Width: {width_fit}")
        print(f"Height: {height_fit}")
        print()
        
        if columns >= art_width and lines >= (art_height + 10):
            print("🎉 Perfect! Your ASCII art will display beautifully!")
            print("=" * min(columns, 80))
            print()
            
            # Display the art
            for line in ascii_lines:
                print(line)
                
            print()
            print("=" * min(columns, 80))
            print("This is how it will appear in the KaliForge II TUI!")
        else:
            print("📱 Terminal too small for full display, but ncurses will handle scaling")
            print("=" * min(columns, 80))
            print()
            
            # Show scaled version
            display_lines = ascii_lines[:min(lines-15, len(ascii_lines))]
            for line in display_lines:
                # Truncate if needed
                display_line = line[:min(columns-2, len(line))]
                print(display_line)
            
            if len(display_lines) < len(ascii_lines):
                print(f"... ({len(ascii_lines) - len(display_lines)} more lines)")
                
            print()
            print("=" * min(columns, 80))
            print("ncurses TUI will center and scale this appropriately!")
    else:
        print("❌ ASCII art file not found!")
        print(f"Looking for: {art_file}")

if __name__ == "__main__":
    show_ascii_art()