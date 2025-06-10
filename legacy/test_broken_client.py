#!/usr/bin/env python3
"""
test_broken_client.py

‘client.py’ protokolünü taklit eder, fakat hash’i orijinal.txt'ten alır,
ciphertext’i bozuk.txt'ten üretir. Böylece kodu değiştirmeden
“bozuk veri” testini yaparız.

Protokol:
 1) Parola (raw bytes)
 2) 32-byte SHA256(orijinal.txt)
 3) 4-byte total_chunks
 4) For each chunk: 4-byte size + chunk bytes  (bozuk.txt içeriğinden şifrelenmiş)
"""

import argparse
import os
import socket
import struct
import ssl
import hashlib
from cryptography.fernet import Fernet

def sha256_bytes(data: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(data)
    return h.digest()

def load_key(path):
    if not os.path.exists(path):
        print(f"[error] Key file '{path}' not found")
        exit(1)
    return open(path, "rb").read().strip()

def split_chunks(data: bytes, size: int):
    for i in range(0, len(data), size):
        yield data[i:i+size]

def main():
    parser = argparse.ArgumentParser(description="TCP bozuk-veri test client")
    parser.add_argument("-H","--host",     required=True, help="Server IP/hostname")
    parser.add_argument("-p","--port",     type=int, required=True, help="Server port")
    parser.add_argument("-k","--key",      default="key.key", help="Fernet key file")
    parser.add_argument("-P","--password", required=True, help="Shared password")
    parser.add_argument("--chunk-size", type=int, default=4096, help="Chunk size (default 4096)")
    parser.add_argument("--use-tls", action="store_true", help="Enable TLS")
    parser.add_argument("--cafile", help="CA file for TLS verification")
    parser.add_argument("orig_file", help="Orijinal dosya (hash için)")
    parser.add_argument("broken_file", help="Bozuk dosya (şifreleme için)")
    args = parser.parse_args()

    # 1) Orijinal dosyadan hash hesapla
    try:
        with open(args.orig_file, "rb") as f:
            orig_data = f.read()
    except Exception as e:
        print(f"[error] Cannot open orijinal file '{args.orig_file}': {e}")
        exit(1)
    file_hash = sha256_bytes(orig_data)
    print(f"[test] SHA256({args.orig_file}) = {file_hash.hex()}")

    # 2) Bozuk dosyadan ciphertext üret
    key = load_key(args.key)
    fernet = Fernet(key)
    try:
        with open(args.broken_file, "rb") as f:
            broken_data = f.read()
    except Exception as e:
        print(f"[error] Cannot open bozuk file '{args.broken_file}': {e}")
        exit(1)
    ciphertext = fernet.encrypt(broken_data)
    print(f"[test] '{args.broken_file}' şifrelendi ({len(ciphertext)} bytes)")

    # 3) Parçalama
    chunks = list(split_chunks(ciphertext, args.chunk_size))
    total_chunks = len(chunks)
    print(f"[test] Total chunks = {total_chunks}")

    # 4) TCP bağlantısı
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if args.use_tls:
        if not args.cafile:
            print("[error] --cafile is required when using --use-tls")
            exit(1)
        context = ssl.create_default_context(cafile=args.cafile)
        conn = context.wrap_socket(raw_sock, server_hostname=args.host)
    else:
        conn = raw_sock

    try:
        conn.connect((args.host, args.port))
    except Exception as e:
        print(f"[error] Cannot connect to {args.host}:{args.port}: {e}")
        exit(1)

    # 5) Protokol akışı: parola → hash → total_chunks → [4B size + chunk]
    pwd_bytes = args.password.encode()
    try:
        conn.sendall(pwd_bytes)
        conn.sendall(file_hash)
        conn.sendall(struct.pack("!I", total_chunks))
        for i, ch in enumerate(chunks, start=1):
            size = len(ch)
            conn.sendall(struct.pack("!I", size))
            conn.sendall(ch)
            print(f"[test] Sent chunk {i}/{total_chunks} ({size} bytes)")
    except Exception as e:
        print(f"[error] Error while sending: {e}")
        conn.close()
        exit(1)

    conn.close()
    print("[test] Bozuk-veri test client finished sending. Server integrity check yapmalı.")

if __name__ == "__main__":
    main()
