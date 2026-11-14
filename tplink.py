#!/usr/bin/env python3
"""
Python CLI / wrapper for TP-Link EC220-G5 Encrypted API (Method 2).
Uses the native Node.js tpEncrypt engine under the hood.
Reads router credentials from .env and protects WAN IP details by default.
"""

import sys
import os
import subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
JS_CLI = os.path.join(SCRIPT_DIR, "tplink.js")

def main():
    if not os.path.exists(JS_CLI):
        print(f"Error: {JS_CLI} not found.")
        sys.exit(1)
    
    cmd = ["node", JS_CLI] + sys.argv[1:]
    try:
        proc = subprocess.run(cmd)
        sys.exit(proc.returncode)
    except FileNotFoundError:
        print("Error: Node.js is required to execute the cryptographic engine.")
        sys.exit(1)

if __name__ == "__main__":
    main()
