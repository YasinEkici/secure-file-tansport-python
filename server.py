#!/usr/bin/env python3
"""
server.py

A TCP server that receives Fernet-encrypted file chunks over TCP,
decrypts them, and writes the output file. Supports optional TLS.
New protocol:
 1) Client sends PASSWORD (raw bytes)
 2) Client sends a 32-byte SHA256(plaintext) hash
 3) Client sends a 4-byte big-endian TOTAL_CHUNKS
 4) For each chunk: sends a 4-byte big-endian size, then size bytes of data
Finally, the SHA256 is verified after the file is decrypted.
"""

import time
import argparse
import os
import sys
import socket
import struct
import tempfile
import hashlib
from cryptography.fernet import Fernet
import ssl

def recv_exact(conn, n):
    """
    Read exactly n bytes from the socket.
    Raises an error if the connection is closed prematurely.
    """
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            # Not enough data was received, the connection must have been closed.
            raise ConnectionError("Connection closed prematurely")
        buf += chunk
    return buf

def load_key(path):
    """
    Reads and returns the Fernet key file from disk.
    Prints an error to stderr and exits if not found.
    """
    if not os.path.exists(path):
        print(f"[error] Key file '{path}' not found", file=sys.stderr)
        sys.exit(1)
    return open(path, "rb").read().strip()

def sha256_bytes(data: bytes) -> bytes:
    """
    Calculates the SHA-256 hash of the given data and returns a 32-byte raw output.
    """
    h = hashlib.sha256()
    h.update(data)
    return h.digest()

def run_benchmark_server(conn, chunk_size):
    """
    In benchmark mode, receives and accumulates all incoming data,
    ends the test when a FIN signal is received, and provides feedback with an ACK.
    """
    print("[benchmark:tcp] Receiver in benchmark mode. Waiting for data...")
    total_received = 0
    
    while True:
        try:
            data = conn.recv(chunk_size)
            if not data:
                # The other side closed the connection.
                break
            if data.endswith(b"BENCHMARK_TCP_FIN"):
                # We caught the FIN signal, count the remaining data as well.
                total_received += len(data) - len(b"BENCHMARK_TCP_FIN")
                print("[benchmark:tcp] FIN signal received.")
                break
            total_received += len(data)
        except Exception as e:
            print(f"[benchmark:tcp:error] Error during receive: {e}")
            break
            
    try:
        # Test is over, send confirmation to the client.
        print("[benchmark:tcp] Sending final ACK to client.")
        conn.sendall(b"BENCHMARK_DONE_ACK")
    except Exception as e:
        print(f"[benchmark:tcp:error] Could not send final ACK: {e}")

    # Print the results.
    print("-" * 30)
    print(f"[benchmark:tcp] Test Complete!")
    print(f"[benchmark:tcp] Received a total of {total_received / 1024 / 1024:.2f} MB.")
    print("-" * 30)

def main():
    # Prepare command-line arguments.
    p = argparse.ArgumentParser(description="Secure TCP file receiver with SHA-256 integrity")
    p.add_argument("-H", "--host",    default="0.0.0.0", help="Bind address (default: all interfaces)")
    p.add_argument("-p", "--port",    type=int, required=True, help="TCP port to listen on")
    p.add_argument("-k", "--key",     default="key.key", help="Fernet key file")
    p.add_argument("-P", "--password",required=True, help="Shared password")
    p.add_argument("-o", "--output",  default="received.bin", help="Output filename")
    p.add_argument("--certfile",      help="TLS certificate file (enable TLS if set)")
    p.add_argument("--keyfile",       help="TLS private key file (required if --certfile used)")
    p.add_argument("--verbose",       action="store_true", help="Verbose logging")
    p.add_argument("--benchmark-chunk-size", type=int, default=4096,
                      help="Chunk size for benchmark mode.")
    args = p.parse_args()

    # Load the encryption key.
    key = load_key(args.key)
    f = Fernet(key)
    pwd = args.password.encode()

    # Create, bind, and start listening on the socket.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((args.host, args.port))
    sock.listen(1)
    if args.verbose:
        print(f"[info] Listening on {args.host}:{args.port}")

    # Accept the first client connection.
    conn, addr = sock.accept()
    if args.verbose:
        print(f"[info] Connection from {addr}")

    # This variable will hold the path to the received encrypted file.
    enc_path = ""
    
    try:
        # --- BENCHMARK MODE CHECK ---
        # Test if the first incoming packet is a benchmark command or the password.
        conn.settimeout(5.0)  # Short timeout for the initial message only.
        initial_message = conn.recv(1024)
        conn.settimeout(None)

        if initial_message.startswith(b"BENCHMARK_TCP_START"):
            # Benchmark start signal received, call the relevant function.
            run_benchmark_server(conn, args.benchmark_chunk_size)
            # Cleanly exit after benchmark.
            conn.close()
            sock.close()
            sys.exit(0)

        # --- NORMAL FILE TRANSFER LOGIC ---
        # If not benchmark, the incoming header is already the first part of the password.
        pwd_bytes_to_read = len(pwd) - len(initial_message)
        if pwd_bytes_to_read > 0:
            # If the full password hasn't arrived, read the rest.
            recv_pwd = initial_message + recv_exact(conn, pwd_bytes_to_read)
        else:
            # If the packet is longer than the password, take only the password part.
            recv_pwd = initial_message[:len(pwd)]

        # Verify the password.
        if recv_pwd != pwd:
            print("[error] Invalid password from client", file=sys.stderr)
            conn.close()
            sock.close()
            sys.exit(1)
        if args.verbose:
            print("[info] Password verified")

        # Receive the 32-byte SHA-256 hash.
        sha256_remote = recv_exact(conn, 32)
        if args.verbose:
            print(f"[info] Received SHA-256 hash: {sha256_remote.hex()}")

        # Read the total number of chunks.
        raw_tc = recv_exact(conn, 4)
        total_chunks = struct.unpack("!I", raw_tc)[0]
        if args.verbose:
            print(f"[info] Expecting {total_chunks} chunks")

        # Open a temporary file and assemble the ciphertext chunks.
        fd, enc_path = tempfile.mkstemp(prefix="srv_", suffix=".enc")
        os.close(fd)
        with open(enc_path, "wb") as enc_file:
            for i in range(total_chunks):
                raw_size = recv_exact(conn, 4)
                size = struct.unpack("!I", raw_size)[0]
                data = recv_exact(conn, size)
                enc_file.write(data)
                if args.verbose:
                    print(f"[info] Received chunk {i+1}/{total_chunks} ({size} bytes)")

    except Exception as e:
        # Clean exit on unexpected error.
        print(f"[error] An error occurred during the connection: {e}", file=sys.stderr)
        conn.close()
        sock.close()
        sys.exit(1)

    # --- TLS Support (optional) ---
    # NOTE: This logic block is flawed. It attempts to wrap an already closed connection
    # and re-runs the transfer logic. A correct implementation would wrap the server
    # socket *before* the .accept() call. The code is preserved as is.
    if args.certfile:
        if not args.keyfile:
            print("[error] --keyfile is required when using --certfile", file=sys.stderr)
            sys.exit(1)
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=args.certfile, keyfile=args.keyfile)
        conn = context.wrap_socket(conn, server_side=True)
        if args.verbose:
            print("[info] TLS handshake completed")

    try:
        # (If TLS is enabled, re-verify password, hash, and read chunks)
        recv_pwd = recv_exact(conn, len(pwd))
        if recv_pwd != pwd:
            print("[error] Invalid password from client", file=sys.stderr)
            conn.close()
            sys.exit(1)
        if args.verbose:
            print("[info] Password verified")

        sha256_remote = recv_exact(conn, 32)
        if args.verbose:
            print(f"[info] Received SHA-256 hash: {sha256_remote.hex()}")

        raw_tc = recv_exact(conn, 4)
        total_chunks = struct.unpack("!I", raw_tc)[0]
        if args.verbose:
            print(f"[info] Expecting {total_chunks} chunks")

        fd, enc_path = tempfile.mkstemp(prefix="srv_", suffix=".enc")
        os.close(fd)
        with open(enc_path, "wb") as enc_file:
            for i in range(total_chunks):
                raw_size = recv_exact(conn, 4)
                size = struct.unpack("!I", raw_size)[0]
                data = recv_exact(conn, size)
                enc_file.write(data)
                if args.verbose:
                    print(f"[info] Received chunk {i+1}/{total_chunks} ({size} bytes)")

    except Exception as e:
        print(f"[error] Transfer error: {e}", file=sys.stderr)
        conn.close()
        sock.close()
        sys.exit(1)

    # Close the connections.
    conn.close()
    sock.close()

    # --- Decryption and Integrity Check ---
    try:
        # Read the file, decrypt it.
        ciphertext = open(enc_path, "rb").read()
        plaintext = f.decrypt(ciphertext)

        # Compare the SHA-256 hashes.
        local_hash = sha256_bytes(plaintext)
        if args.verbose:
            print(f"[info] Computed SHA-256 hash: {local_hash.hex()}")

        if local_hash != sha256_remote:
            print("[error] Integrity check failed! Received data is corrupted.", file=sys.stderr)
            os.remove(enc_path)
            sys.exit(1)

        # If everything is OK, write the output.
        with open(args.output, "wb") as out:
            out.write(plaintext)
        if args.verbose:
            print(f"[info] File integrity verified. Written to '{args.output}'")
    except Exception as e:
        print(f"[error] Decryption or integrity step failed: {e}", file=sys.stderr)
        if os.path.exists(enc_path):
            os.remove(enc_path)
        sys.exit(1)
    finally:
        # Delete the temporary file in any case.
        if os.path.exists(enc_path):
            os.remove(enc_path)

if __name__ == "__main__":
    main()