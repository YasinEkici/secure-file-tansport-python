#!/usr/bin/env python3
"""
client.py 
- Benchmark and file-transfer modes are clearly separated.
- Protocol is 100% compatible with the current server.
"""

import argparse
import os
import sys
import socket
import struct
import ssl
import hashlib
import time
from cryptography.fernet import Fernet

def load_key(path):
    """
    Load the Fernet key from the given file path.
    Exit with error if the file does not exist.
    """
    if not os.path.exists(path):
        print(f"[error] Key file '{path}' not found", file=sys.stderr)
        sys.exit(1)
    with open(path, "rb") as key_file:
        return key_file.read().strip()

def sha256_bytes(data: bytes) -> bytes:
    """
    Compute SHA-256 hash of the given bytes and return the digest.
    """
    h = hashlib.sha256()
    h.update(data)
    return h.digest()

def split_chunks(data: bytes, chunk_size: int):
    """
    Yield successive data chunks of size <= chunk_size.
    """
    for i in range(0, len(data), chunk_size):
        yield data[i:i + chunk_size]

def run_benchmark_client(args, conn):
    """
    Perform a realistic TCP throughput benchmark by sending
    a fixed amount of data and measuring the transfer rate.
    """
    print("[benchmark:tcp] Starting REALISTIC TCP throughput benchmark...")
    BENCHMARK_SIZE_MB = 10
    BENCHMARK_SIZE_BYTES = BENCHMARK_SIZE_MB * 1024 * 1024
    payload = b'\x01' * args.chunk_size

    try:
        conn.sendall(b"BENCHMARK_TCP_START")
        print(f"[benchmark:tcp] Sending {BENCHMARK_SIZE_MB} MB of data...")
        start_time = time.perf_counter()
        sent = 0
        while sent < BENCHMARK_SIZE_BYTES:
            conn.sendall(payload)
            sent += len(payload)
        conn.sendall(b"BENCHMARK_TCP_FIN")
        print("[benchmark:tcp] All data sent, waiting for final ACK...")
        final_ack = conn.recv(1024)
        if final_ack == b"BENCHMARK_DONE_ACK":
            end_time = time.perf_counter()
            duration = end_time - start_time
            if duration > 0:
                mbps = (sent * 8) / (duration * 1_000_000)
                print("-" * 30)
                print("[benchmark:tcp] Realistic Test Complete!")
                print(f"[benchmark:tcp] Sent {sent/1024/1024:.2f} MB in {duration:.2f} s")
                print(f"[benchmark:tcp] Realistic TCP Throughput: {mbps:.2f} Mbps")
                print("-" * 30)
    except Exception as e:
        print(f"[benchmark:tcp:error] An error occurred: {e}", file=sys.stderr)
    finally:
        conn.close()

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Secure TCP file sender")
    parser.add_argument("-H", "--host", required=True, help="Server IP or hostname")
    parser.add_argument("-p", "--port", type=int, required=True, help="Server TCP port")
    parser.add_argument("-k", "--key", default="key.key", help="Path to the Fernet key file")
    parser.add_argument("-P", "--password", required=True, help="Shared password for authentication")
    parser.add_argument("--chunk-size", type=int, default=4096, help="Size of each data chunk in bytes")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--benchmark", action="store_true", help="Run a TCP bandwidth benchmark instead of file transfer")
    parser.add_argument("input", nargs='?', default=None, help="Input file to send (omit for benchmark mode)")
    args = parser.parse_args()

    # Ensure a file is provided when not benchmarking
    if not args.benchmark and not args.input:
        parser.error("File transfer mode requires an 'input' file.")

    # Establish a TCP connection to the server
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((args.host, args.port))
        if args.verbose:
            print(f"[info] Connected to {args.host}:{args.port}")
    except Exception as e:
        print(f"[error] Unable to connect: {e}", file=sys.stderr)
        sys.exit(1)

    # If benchmark flag is set, run benchmark and exit
    if args.benchmark:
        run_benchmark_client(args, sock)
        sys.exit(0)

    # Otherwise, proceed with secure file transfer
    try:
        # Read the entire input file
        with open(args.input, "rb") as f:
            plaintext = f.read()

        # Compute SHA-256 hash of plaintext
        file_hash = sha256_bytes(plaintext)

        # Load Fernet key and encrypt the plaintext
        key = load_key(args.key)
        fernet = Fernet(key)
        ciphertext = fernet.encrypt(plaintext)

        # Split ciphertext into chunks
        chunks = list(split_chunks(ciphertext, args.chunk_size))
        total_chunks = len(chunks)

        if args.verbose:
            print(f"[info] SHA-256 hash: {file_hash.hex()}")
            print(f"[info] Encrypted data size: {len(ciphertext)} bytes in {total_chunks} chunks")

        # Send authentication password
        sock.sendall(args.password.encode())

        # Send file hash and number of chunks
        sock.sendall(file_hash)
        sock.sendall(struct.pack("!I", total_chunks))

        # Send each chunk with its size header
        for chunk in chunks:
            sock.sendall(struct.pack("!I", len(chunk)))
            sock.sendall(chunk)

        print("[info] File transfer complete.")

    except Exception as e:
        print(f"[error] Error during file transfer: {e}", file=sys.stderr)
    finally:
        sock.close()
        if args.verbose:
            print("[info] Connection closed.")

if __name__ == "__main__":
    main()
