#!/usr/bin/env python3
"""
test_broken_sender.py

‘ip_sender.py’ protokolünü taklit eder, fakat hash’i orijinal_udp.txt'ten alır,
ciphertext’i bozuk_udp.txt'ten üretir. Böylece kodu değiştirmeden
“bozuk veri” testini yaparız.

Protokol:
 1) İlk UDP paket: [PASSWORD][b"HASH"][32-byte SHA256(orijinal_udp.txt)]
 2) Sonraki paketler: [PASSWORD][4 B idx][4 B total][chunk] (bozuk_udp.txt'ten şifrelenmiş)
"""

import argparse
import os
import sys
import struct
import random
import socket
import hashlib
from cryptography.fernet import Fernet
from scapy.all import IP, UDP, Raw, send, fragment, conf, get_if_list

def detect_loopback_iface():
    for ifc in get_if_list():
        name = ifc.lower()
        if "loopback" in name or name.startswith("lo"):
            return ifc
    return conf.iface

def load_key(path):
    if not os.path.exists(path):
        print(f"[error] key file '{path}' not found", file=sys.stderr)
        sys.exit(1)
    return open(path, "rb").read().strip()

def sha256_bytes(data: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(data)
    return h.digest()

def chunkify(data: bytes, header_size: int, mtu: int):
    payload = mtu - 28 - header_size  # 20 IP + 8 UDP
    for i in range(0, len(data), payload):
        yield data[i : i + payload]

def main():
    parser = argparse.ArgumentParser(description="UDP bozuk-veri test sender")
    parser.add_argument("-H","--host",     required=True, help="Receiver IP")
    parser.add_argument("-p","--port", type=int, default=12345, help="UDP port")
    parser.add_argument("-k","--key",      default="key.key", help="Fernet key file")
    parser.add_argument("-P","--password", required=True, help="Shared password")
    parser.add_argument("--mtu",    type=int, default=1500, help="MTU for fragmentation")
    parser.add_argument("--verify", action="store_true", help="Verbose & checksum verify")
    parser.add_argument("orig_file", help="Orijinal dosya (hash için)")
    parser.add_argument("broken_file", help="Bozuk dosya (şifreleme için)")
    args = parser.parse_args()

    # Arayüzü otomatik seç
    iface = detect_loopback_iface()
    if args.verify:
        print(f"[test] Auto-detected interface: {iface}")

    # 1) Orijinal dosyadan hash hesapla
    try:
        with open(args.orig_file, "rb") as f:
            orig = f.read()
    except Exception as e:
        print(f"[error] Cannot open {args.orig_file}: {e}")
        sys.exit(1)
    file_hash = sha256_bytes(orig)
    if args.verify:
        print(f"[test] SHA256({args.orig_file}) = {file_hash.hex()}")

    # 2) Bozuk dosyadan ciphertext üret
    key = load_key(args.key)
    fernet = Fernet(key)
    try:
        with open(args.broken_file, "rb") as f:
            broken = f.read()
    except Exception as e:
        print(f"[error] Cannot open {args.broken_file}: {e}")
        sys.exit(1)
    ciphertext = fernet.encrypt(broken)
    total_chunks = sum(1 for _ in chunkify(ciphertext, len(args.password.encode())+8, args.mtu))
    if args.verify:
        print(f"[test] '{args.broken_file}' şifrelendi, total_chunks = {total_chunks}")

    # 3) Hash paketi: [PASSWORD][b"HASH"][32-byte file_hash]
    pwd_b = args.password.encode()
    hash_header = pwd_b + b"HASH" + file_hash
    pkt_hash = IP(dst=args.host, ttl=64, id=random.getrandbits(16)) / \
               UDP(dport=args.port, sport=random.randint(1024,65535)) / \
               Raw(load=hash_header)
    send(pkt_hash, iface=iface, verbose=False)
    print("[test] Sent HASH packet")

    # 4) Ciphertext chunk’ları [PASSWORD][4B idx][4B total][chunk]
    header_sz = len(pwd_b) + 8
    for idx, chunk in enumerate(chunkify(ciphertext, header_sz, args.mtu)):
        header = pwd_b + struct.pack("!II", idx, total_chunks)
        pkt = IP(dst=args.host, ttl=64, id=random.getrandbits(16)) / \
              UDP(dport=args.port, sport=random.randint(1024,65535)) / \
              Raw(load=header + chunk)
        for frag in fragment(pkt, fragsize=args.mtu-28):
            if args.verify:
                frag = frag.__class__(bytes(frag))
            send(frag, iface=iface, verbose=False)
        print(f"[test] Sent chunk {idx+1}/{total_chunks}")

    print("[test] Bozuk-veri test sender finished sending.")

if __name__ == "__main__":
    main()
