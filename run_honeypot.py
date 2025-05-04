#!/usr/bin/env python3
"""QryptX Honeypot Launcher"""
import sys
import os
import argparse

def check_root():
    """Check if the script is run with root privileges"""
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:  # Unix-like
        return os.geteuid() == 0

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='QryptX Honeypot')
    parser.add_argument('--dev', action='store_true', help='Run in development mode (no root required)')
    args = parser.parse_args()

    if not args.dev and not check_root():
        print("Error: This script must be run with administrator/root privileges")
        print("Windows: Right-click and select 'Run as administrator'")
        print("Linux/Unix: Run with sudo")
        print("\nOr use --dev flag to run in development mode with non-privileged ports")
        sys.exit(1)

    try:
        # Add the current directory to Python path
        sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
        
        # Import directly from the local qryptx module
        from qryptx import main as honeypot_main
        honeypot_main()
    except ImportError as e:
        print(f"Import Error: {e}")
        print("Error: QryptX package not found. Make sure you have installed all requirements:")
        print("pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"Error starting honeypot: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()