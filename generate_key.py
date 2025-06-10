#!/usr/bin/env python3
"""
generate_key.py

Generates and saves a new Fernet key to a file, with optional backup and secure permissions.
"""

import os
import sys
import argparse
from cryptography.fernet import Fernet
from datetime import datetime

def backup_file(path: str):
    """Rename existing key file with a timestamped backup suffix."""
    if os.path.exists(path):
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        backup_path = f"{path}.{timestamp}.bak"
        os.rename(path, backup_path)
        print(f"[info] Existing key file backed up to {backup_path}")

def write_key(path: str, key: bytes):
    """Write the key to disk and restrict file permissions."""
    with open(path, "wb") as f:
        f.write(key)
    os.chmod(path, 0o600)
    print(f"[info] New key written to {path} with permissions 600")

def main():
    parser = argparse.ArgumentParser(description="Generate a new Fernet key")
    parser.add_argument(
        "-o", "--output", default="key.key",
        help="Path to key file (default: key.key)"
    )
    parser.add_argument(
        "--no-backup", action="store_true",
        help="Skip backing up an existing key file"
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Overwrite without prompting"
    )
    args = parser.parse_args()

    key_path = args.output

    # Confirm and backup existing key if needed
    if os.path.exists(key_path) and not args.no_backup:
        if not args.force:
            resp = input(f"File '{key_path}' exists. Backup and overwrite? [y/N]: ").strip().lower()
            if resp not in ("y", "yes"):
                print("Aborted by user.")
                sys.exit(0)
        backup_file(key_path)

    # Generate and write new key
    new_key = Fernet.generate_key()
    write_key(key_path, new_key)

if __name__ == "__main__":
    main()
