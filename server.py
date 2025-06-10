#!/usr/bin/env python3
"""
server.py 
- Correctly handles TCP stream processing.
- Reads each protocol element (password, hash, chunk) in sequence and full length.
- Safely releases resources in all cases.
"""

import argparse
import os
import sys
import socket
import struct
import tempfile
import hashlib
from cryptography.fernet import Fernet

def recv_exact(conn, n):
    """
    Read exactly n bytes from the socket.
    Raise ConnectionError if the connection closes unexpectedly.
    """
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly.")
        buf += chunk
    return buf

def load_key(path):
    """
    Load the Fernet key from disk.
    Exit with error if the file does not exist.
    """
    if not os.path.exists(path):
        print(f"[error] Key file '{path}' not found.", file=sys.stderr)
        sys.exit(1)
    with open(path, "rb") as key_file:
        return key_file.read().strip()

def sha256_bytes(data: bytes) -> bytes:
    """
    Compute SHA-256 digest of the given data.
    """
    h = hashlib.sha256()
    h.update(data)
    return h.digest()

def handle_connection(conn, args, key, pwd):
    """
    Handle a single client connection from start to finish.
    """
    enc_path = None
    fernet = Fernet(key)
    try:
        # --- Protocol: read fields in order ---
        
        # 1. Read password (exactly the length of pwd)
        recv_pwd = recv_exact(conn, len(pwd))
        if recv_pwd != pwd:
            print("[error] Invalid password from client.", file=sys.stderr)
            return
        if args.verbose:
            print("[info] Password validated.")

        # 2. Read SHA-256 hash (32 bytes)
        sha256_remote = recv_exact(conn, 32)
        if args.verbose:
            print(f"[info] Received SHA-256 hash: {sha256_remote.hex()}")

        # 3. Read total chunk count (4-byte unsigned int)
        raw_tc = recv_exact(conn, 4)
        total_chunks = struct.unpack("!I", raw_tc)[0]
        if args.verbose:
            print(f"[info] Expected number of chunks: {total_chunks}")

        # Security check: reject excessively large chunk counts
        if total_chunks > 200_000:  # roughly up to ~800 MB
            raise ValueError(f"Chunk count ({total_chunks}) is unreasonably high.")

        # 4. Read all chunks in sequence into a temporary file
        fd, enc_path = tempfile.mkstemp(prefix="srv_", suffix=".enc")
        os.close(fd)
        with open(enc_path, "wb") as enc_file:
            for i in range(total_chunks):
                # Read chunk size (4 bytes)
                raw_size = recv_exact(conn, 4)
                size = struct.unpack("!I", raw_size)[0]
                # Read the chunk data exactly 'size' bytes
                data = recv_exact(conn, size)
                enc_file.write(data)

        # 5. Verify file integrity and write plaintext output
        with open(enc_path, "rb") as enc_file:
            ciphertext = enc_file.read()

        plaintext = fernet.decrypt(ciphertext)
        local_hash = sha256_bytes(plaintext)
        if args.verbose:
            print(f"[info] Computed SHA-256: {local_hash.hex()}")

        if local_hash != sha256_remote:
            print("[error] Integrity check failed! Data is corrupted.", file=sys.stderr)
        else:
            with open(args.output, "wb") as out_file:
                out_file.write(plaintext)
            print(f"[info] Integrity verified. Saved as '{args.output}'.")

    except (ConnectionError, struct.error) as e:
        print(f"[error] Protocol error during transfer: {e}", file=sys.stderr)
    except Exception as e:
        print(f"[error] Unexpected error: {e}", file=sys.stderr)
    finally:
        # Always close connection and remove temporary file
        if args.verbose:
            print("[info] Closing client connection.")
        conn.close()
        if enc_path and os.path.exists(enc_path):
            os.remove(enc_path)

def main():
    parser = argparse.ArgumentParser(description="Secure TCP file receiver")
    parser.add_argument("-p", "--port", type=int, required=True, help="TCP port to listen on")
    parser.add_argument("-P", "--password", required=True, help="Shared password for authentication")
    parser.add_argument("-k", "--key", default="key.key", help="Path to the Fernet key file")
    parser.add_argument("-o", "--output", default="received_tcp.bin", help="Output filename for the received file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    key = load_key(args.key)
    pwd = args.password.encode()

    # Set up listening socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", args.port))
    sock.listen(5)
    print(f"[info] Server listening on port {args.port}...")

    try:
        # Accept a single connection and handle it
        conn, addr = sock.accept()
        if args.verbose:
            print(f"[info] Accepted connection from {addr}.")
        handle_connection(conn, args, key, pwd)
    except KeyboardInterrupt:
        print("\n[info] Shutting down server.")
    finally:
        print("[info] Closing server socket and exiting.")
        sock.close()

if __name__ == "__main__":
    main()
