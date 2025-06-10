#!/usr/bin/env python3
"""
client.py

TCP client: Encrypts files with Fernet, splits them into chunks, and sends to the server.
Protocol flow:
 1) Sends the password (PASSWORD) as raw bytes.
 2) Sends the SHA-256(plaintext) hash of the file (32 bytes).
 3) Sends the total number of chunks as a 4-byte big-endian integer.
 4) For each chunk, sends a 4-byte length prefix, followed by the data.
Optionally supports TLS.
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
    # Reads the key file, exits with an error if not found.
    if not os.path.exists(path):
        print(f"[error] Key file '{path}' not found", file=sys.stderr)
        sys.exit(1)
    # Opens the file in binary mode and returns its content (a Fernet key is 44-byte ASCII).
    return open(path, "rb").read().strip()

def sha256_bytes(data: bytes) -> bytes:
    # Calculates the SHA-256 hash of raw data and returns the raw byte output.
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.digest()

def split_chunks(data: bytes, chunk_size: int):
    # Generator to split data into chunks of a given size.
    for i in range(0, len(data), chunk_size):
        yield data[i : i + chunk_size]

def run_benchmark_client(args, conn):
    """
    Performs a realistic speed test over a TCP connection:
    - Sends 10 MB of data,
    - Measures time with start/end ACKs,
    - Calculates the instantaneous speed in Mbps.
    """
    print("[benchmark:tcp] Starting REALISTIC TCP throughput benchmark...")
    BENCHMARK_SIZE_MB = 10
    BENCHMARK_SIZE_BYTES = BENCHMARK_SIZE_MB * 1024 * 1024
    payload = b'\x01' * args.chunk_size  # A constant byte array

    try:
        # Send a test start message to the server
        conn.sendall(b"BENCHMARK_TCP_START")
        print(f"[benchmark:tcp] Sending {BENCHMARK_SIZE_MB} MB of data...")
        start_time = time.time()

        sent = 0
        while sent < BENCHMARK_SIZE_BYTES:
            conn.sendall(payload)
            sent += len(payload)

        # End of test message
        conn.sendall(b"BENCHMARK_TCP_FIN")
        print("[benchmark:tcp] All data sent, waiting for final ACK from server...")

        # Wait for the final ACK from the server
        final_ack = conn.recv(1024)
        if final_ack == b"BENCHMARK_DONE_ACK":
            end_time = time.time()
            duration = end_time - start_time
            if duration > 0:
                mbps = (sent * 8) / (duration * 1_000_000)
                print("-" * 30)
                print("[benchmark:tcp] Realistic Test Complete!")
                print(f"[benchmark:tcp] {sent/1024/1024:.2f} MB in {duration:.2f} s")
                print(f"[benchmark:tcp] Throughput: {mbps:.2f} Mbps")
                print("-" * 30)
        else:
            print("[benchmark:tcp:error] Did not receive final ACK from server.")

    except Exception as e:
        print(f"[benchmark:tcp:error] An error occurred: {e}", file=sys.stderr)
    finally:
        conn.close()

def main():
    # Define command-line arguments
    parser = argparse.ArgumentParser(
        description="Secure TCP file sender with SHA-256 integrity"
    )
    parser.add_argument("-H", "--host", required=True, help="Server IP or hostname")
    parser.add_argument("-p", "--port", type=int, required=True, help="Server TCP port")
    parser.add_argument("-k", "--key", default="key.key", help="Fernet key file")
    parser.add_argument("-P", "--password", required=True, help="Shared password")
    parser.add_argument("--chunk-size", type=int, default=4096,
                        help="Chunk size in bytes (default: 4096)")
    parser.add_argument("--use-tls", action="store_true",
                        help="Enable TLS for the TCP connection")
    parser.add_argument("--cafile", help="CA certificate file (required with --use-tls)")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--benchmark", action="store_true",
                        help="Run a TCP bandwidth benchmark.")
    parser.add_argument("input", nargs='?', default=None,
                        help="Input file to send (not for benchmark mode)")
    args = parser.parse_args()

    # If not in benchmark mode, a filename is required
    if not args.benchmark and not args.input:
        print("[error] An input file is required for file transfer mode.", file=sys.stderr)
        sys.exit(1)

    # Create the socket and wrap it with TLS if necessary
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if args.use_tls:
        if not args.cafile:
            print("[error] --cafile is required when using --use-tls", file=sys.stderr)
            sys.exit(1)
        context = ssl.create_default_context(cafile=args.cafile)
        conn = context.wrap_socket(raw_sock, server_hostname=args.host)
        if args.verbose:
            print("[info] TLS context created; connecting with verification")
    else:
        conn = raw_sock

    # Connect to the server
    try:
        conn.connect((args.host, args.port))
    except Exception as e:
        print(f"[error] Unable to connect to {args.host}:{args.port}: {e}", file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        print(f"[info] Connected to {args.host}:{args.port}")

    # If benchmark mode is selected, run the test and exit
    if args.benchmark:
        run_benchmark_client(args, conn)
        sys.exit(0)

    # Normal file transfer flow
    try:
        # Read the file
        try:
            with open(args.input, "rb") as f:
                plaintext = f.read()
        except Exception as e:
            print(f"[error] Cannot open input file '{args.input}': {e}", file=sys.stderr)
            sys.exit(1)

        # Get the raw SHA-256 hash of the file
        file_hash = sha256_bytes(plaintext)
        if args.verbose:
            print(f"[info] SHA-256(plaintext) = {file_hash.hex()}")

        # Load the Fernet key and encrypt
        key = load_key(args.key)
        fernet = Fernet(key)
        ciphertext = fernet.encrypt(plaintext)
        if args.verbose:
            print(f"[info] Encrypted '{args.input}' → {len(ciphertext)} bytes")

        # Split the encrypted data into chunks
        chunks = list(split_chunks(ciphertext, args.chunk_size))
        total_chunks = len(chunks)
        if args.verbose:
            print(f"[info] Split into {total_chunks} chunks (size: {args.chunk_size})")

        # 1) Send the password
        conn.sendall(args.password.encode())
        if args.verbose:
            print("[info] Sent password")

        # 2) Send the hash
        conn.sendall(file_hash)
        if args.verbose:
            print("[info] Sent SHA-256 hash")

        # 3) Send the number of chunks
        conn.sendall(struct.pack("!I", total_chunks))
        if args.verbose:
            print(f"[info] Sent total_chunks = {total_chunks}")

        # 4) Send each chunk with its length prefix
        for idx, chunk in enumerate(chunks, start=1):
            size = len(chunk)
            conn.sendall(struct.pack("!I", size))
            conn.sendall(chunk)
            if args.verbose:
                print(f"[info] Sent chunk {idx}/{total_chunks} ({size} bytes)")

    except Exception as e:
        print(f"[error] Error during file transfer: {e}", file=sys.stderr)
    finally:
        # Close the connection in all cases
        conn.close()
        if args.verbose:
            print("[info] Connection closed.")

if __name__ == "__main__":
    main()