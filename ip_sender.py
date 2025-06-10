#!/usr/bin/env python3
"""
ip_sender.py

Detects interfaces using Scapy's own interface object directly,
instead of a "friendly name", to ensure maximum compatibility.
"""

import argparse
import os
import struct
import random
import sys
import threading
import socket
import time
import hashlib
from cryptography.fernet import Fernet
# Specific imports are used instead of scapy.all to properly use conf.ifaces.
from scapy.config import conf
from scapy.sendrecv import srp, sendp
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP, fragment
from scapy.packet import Raw

### MODIFIED HELPER FUNCTION: NOW RETURNS THE INTERFACE OBJECT ###
def get_interface_object(friendly_name: str):
    """
    Returns the Scapy interface object corresponding to the given friendly name (e.g., "Wi-Fi").
    """
    for iface in conf.ifaces.values():
        if iface.name == friendly_name:
            print(f"[info] '{friendly_name}' arayüzü bulundu ve nesne olarak seçildi.")
            return iface  # <-- THE OBJECT ITSELF IS NOW RETURNED
    
    print(f"[fatal] '{friendly_name}' isimli arayüz bulunamadı!", file=sys.stderr)
    print("Mevcut arayüzler ve isimleri:", file=sys.stderr)
    for iface in conf.ifaces.values():
        print(f"  - İsim: '{iface.name}', ID: {iface.id}", file=sys.stderr)
    sys.exit(1)


def load_key(path):
    if not os.path.exists(path):
        print(f"[error] key file '{path}' not found", file=sys.stderr)
        sys.exit(1)
    return open(path, 'rb').read().strip()

def sha256_bytes(data: bytes) -> bytes:
    h = hashlib.sha256(); h.update(data); return h.digest()

def get_mac_robustly(target_ip: str, iface_obj, retries: int = 3, timeout: int = 2) -> str | None:
    """
    Finds the MAC address using the interface object directly for ARP requests.
    """
    print(f"[info] MAC adresi {target_ip} için '{iface_obj.name}' arayüzü üzerinden çözümleniyor...")
    for i in range(retries):
        try:
            # Send an ARP request to find the MAC of the target IP.
            answered, unanswered = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip),
                iface=iface_obj,  # <-- NOW USING THE OBJECT DIRECTLY
                timeout=timeout,
                verbose=False,
                inter=0.1
            )
            if answered:
                dest_mac = answered[0][1].src
                print(f"[info] Başarılı: MAC adresi bulundu -> {dest_mac}")
                return dest_mac
            else:
                print(f"[warn] MAC çözümleme denemesi {i+1}/{retries} zaman aşımına uğradı.")
        except Exception as e:
            print(f"[warn] MAC çözümleme sırasında hata oluştu (deneme {i+1}): {e}")
    
    print(f"[error] {retries} deneme sonrası MAC adresi çözümlenemedi.")
    return None

def run_benchmark(args, dest_mac, iface_obj):
    """Runs a benchmark test to measure maximum send throughput."""
    print("[benchmark] UDP benchmark testi başlatılıyor...")
    
    BENCHMARK_SIZE_MB = 100
    BENCHMARK_SIZE_BYTES = BENCHMARK_SIZE_MB * 1024 * 1024
    # Create a payload that fills the MTU (minus Ethernet, IP, and UDP headers).
    payload = b'\x00' * (args.mtu - 28) 
    total_sent = 0
    start_time = time.perf_counter()
    
    print(f"[benchmark] {args.host} adresine {BENCHMARK_SIZE_MB} MB veri gönderiliyor...")
    
    # Send data as fast as possible.
    while total_sent < BENCHMARK_SIZE_BYTES:
        pkt = Ether(dst=dest_mac) / IP(dst=args.host) / UDP(sport=random.randint(1024,65535), dport=args.port) / payload
        sendp(pkt, iface=iface_obj, verbose=False) # <-- NOW USING THE OBJECT DIRECTLY
        total_sent += len(payload)
        
    end_time = time.perf_counter()
    duration = end_time - start_time
    
    if duration > 0:
        throughput_mbps = (total_sent * 8) / (duration * 1000 * 1000)
        print("-" * 30, f"\n[benchmark] Test Tamamlandı!",
              f"\n[benchmark] {total_sent / 1024 / 1024:.2f} MB veri {duration:.2f} saniyede gönderildi.",
              f"\n[benchmark] Maksimum Gönderim Hızı: {throughput_mbps:.2f} Mbps\n" + "-" * 30)
    else:
        print("[benchmark] Test, ölçüm yapılamayacak kadar hızlı tamamlandı.")

    # Send a final packet to signal the end of the benchmark to the receiver.
    fin_pkt = Ether(dst=dest_mac) / IP(dst=args.host) / UDP(sport=random.randint(1024,65535), dport=args.port) / b"BENCHMARK_FIN"
    sendp(fin_pkt, iface=iface_obj, verbose=False)

def main():
    parser = argparse.ArgumentParser(description="IP-layer sender with robust interface handling")
    parser.add_argument('-H','--host', required=True, help="Receiver IP")
    parser.add_argument('-p','--port', type=int, default=12345, help="UDP port")
    parser.add_argument('-P','--password', required=True, help="Shared password")
    parser.add_argument('-k','--key', default='key.key', help="Fernet key file")
    parser.add_argument('--mtu', type=int, default=1500, help="IP fragment size")
    parser.add_argument('--verify', action='store_true', help="Verbose logging")
    parser.add_argument('--iface', required=True, help="Network interface's friendly name (e.g., 'Wi-Fi')")
    parser.add_argument('--benchmark', action='store_true', help="Run a bandwidth benchmark")
    parser.add_argument('input', nargs='?', default=None, help="File to send")
    
    args = parser.parse_args()

    # Ensure an input file is provided if not in benchmark mode.
    if not args.benchmark and not args.input:
        parser.error("File transfer mode requires an 'input' file.")

    # Get the Scapy interface object and target MAC address.
    iface_obj = get_interface_object(args.iface)
    dest_mac = get_mac_robustly(args.host, iface_obj)
    if not dest_mac:
        sys.exit(f"[fatal] MAC adresi {args.host} için bulunamadı. Program durduruluyor.")

    # If in benchmark mode, run the benchmark and exit.
    if args.benchmark:
        run_benchmark(args, dest_mac, iface_obj)
        sys.exit(0)

    # --- RELIABLE FILE TRANSFER LOGIC ---
    # Read, hash, and encrypt the file.
    pt = open(args.input,'rb').read()
    file_hash = sha256_bytes(pt)
    key = load_key(args.key)
    fernet = Fernet(key)
    ct = fernet.encrypt(pt)

    # Prepare for chunking based on MTU.
    pwd_b = args.password.encode()
    ip_payload_size = args.mtu - 28 # Max data in one IP packet (Ethernet, IP, UDP headers).
    app_header_size = len(pwd_b) + len(b"DATA") + 8 # Our custom header: PWD + "DATA" + index + total.
    app_chunk_size = ip_payload_size - app_header_size # Max application data per UDP payload.
    chunks = [ct[i:i+app_chunk_size] for i in range(0, len(ct), app_chunk_size)]
    total = len(chunks)

    # Setup control socket for receiving ACKs/NACKs.
    ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ctrl_sock.bind(('', args.port+1))
    ctrl_sock.settimeout(2.0)

    # Threading events for synchronization.
    handshake_done = threading.Event()
    finished_event = threading.Event()

    def send_chunk(idx):
        """Constructs and sends a single chunk, handling IP fragmentation."""
        hdr = pwd_b + b"DATA" + struct.pack('!II', idx, total)
        payload = hdr + chunks[idx]
        pkt_id = random.getrandbits(16)
        # Create the full UDP packet. Scapy will handle fragmentation if it's too large.
        ip_part = IP(dst=args.host, ttl=64, id=pkt_id) / UDP(dport=args.port, sport=random.randint(1024,65535)) / Raw(load=payload)
        frags = fragment(ip_part, fragsize=ip_payload_size)
        # Send each fragment at Layer 2.
        for f in frags:
            sendp(Ether(dst=dest_mac)/f, iface=iface_obj, verbose=False)
        if args.verify:
            print(f"[info] Chunk {idx+1}/{total} gönderildi (IP.id={pkt_id})")

    def control_listener():
        """Listens for control messages (HASH_ACK, NACK, ACK) from the receiver."""
        while not finished_event.is_set():
            try:
                data, addr = ctrl_sock.recvfrom(65535)
                # Authenticate the message.
                if not data.startswith(pwd_b): continue
                body = data[len(pwd_b):]

                if body == b"HASH_ACK":
                    if args.verify: print(f"[info] HASH_ACK alındı: {addr}")
                    handshake_done.set()
                elif body.startswith(b"NACK"):
                    if not handshake_done.is_set(): continue # Ignore NACKs before handshake.
                    indices_str = body[4:].decode()
                    if args.verify: print(f"[info] NACK alındı (indeksler: {indices_str})")
                    # Resend the requested missing chunks.
                    try:
                        missing_indices = [int(ns) for ns in indices_str.split(',') if ns]
                        for idx in missing_indices:
                            if 0 <= idx < total: send_chunk(idx)
                    except (ValueError, IndexError): pass
                elif body == b"ACK":
                    if args.verify: print(f"[info] Son ACK alındı: {addr}")
                    finished_event.set() # Signal that the transfer is complete.
            except (socket.timeout, ConnectionResetError):
                continue
    
    # Start the listener thread.
    listener = threading.Thread(target=control_listener, daemon=True)
    listener.start()

    # 1. Send the initial hash packet to start the handshake.
    hash_hdr = pwd_b + b"HASH" + file_hash
    pkt_h = Ether(dst=dest_mac) / IP(dst=args.host, ttl=64) / UDP(dport=args.port) / Raw(load=hash_hdr)
    sendp(pkt_h, iface=iface_obj, verbose=False)
    print("[info] SHA-256 hash paketi gönderildi.")

    # 2. Wait for the handshake to complete.
    if not handshake_done.wait(timeout=10.0):
        sys.exit("[error] Handshake zaman aşımına uğradı. Alıcı çalışıyor mu?")
        
    # 3. Handshake is done, send all chunks for the first time.
    print("[info] HASH_HANDSHAKE tamamlandı, tüm chunk'lar gönderiliyor...")
    for idx in range(total): send_chunk(idx)

    # 4. Wait for the final ACK, relying on the listener to handle NACKs.
    print("[info] İlk gönderim tamamlandı. NACK veya son ACK bekleniyor...")
    finished_event.wait()
    ctrl_sock.close()
    print("[info] Transfer tamamlandı. Çıkılıyor.")

if __name__=="__main__":
    main()