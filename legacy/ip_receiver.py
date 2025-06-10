#!/usr/bin/env python3
"""
ip_receiver.py — Scapy ile UDP port 12345'i dinler,
IP başlığı doğrular (TTL, flags, checksum) ve
payload’u application-fragmentation’a göre birleştirip çözer.
"""

from scapy.all import sniff, IP, UDP, raw
from scapy.utils import checksum as scapy_checksum
from cryptography.fernet import Fernet
import struct

# --- Sabitler ---
KEY_FILE   = "key.key"
PASSWORD   = b"SuperSecretPassword123!"
OUTPUT_FILE= "received_scapy_decrypted.bin"

# --- Fernet setup ---
with open(KEY_FILE, "rb") as kf:
    key = kf.read()
fernet = Fernet(key)

# Global veri buffer
buffered = []
expected_chunks = None

def ip_checksum_ok(pkt):
    # Raw IP header bytes
    ihl = pkt.ihl * 4
    hdr = raw(pkt)[:ihl]
    # Sıfırlanmış checksum alanı (bayt 10-12)
    hdr_zero = hdr[:10] + b'\x00\x00' + hdr[12:]
    # Hesapla
    comp = scapy_checksum(hdr_zero)
    return comp == pkt.chksum

def handle_packet(pkt):
    global expected_chunks, buffered

    if IP not in pkt or UDP not in pkt or pkt[UDP].dport != 12345:
        return

    ip = pkt[IP]
    # 1) TTL kontrolü (örnek: TTL>=1)
    print(f"[IP] TTL={ip.ttl}, flags={ip.flags}, chksum={hex(ip.chksum)}")
    if not ip_checksum_ok(ip):
        print("[-] IP checksum mismatch, paketi atıyorum.")
        return
    print("[+] IP checksum doğru.")

    data = bytes(pkt[UDP].payload)
    # İlk 4 byte: toplam parça sayısı (sadece ilk pakette)
    if expected_chunks is None:
        expected_chunks = struct.unpack('!I', data[:4])[0]
        print(f"[+] Beklenen parça sayısı (app-layer): {expected_chunks}")
        chunk = data[4:]
    else:
        # Her paket başında 4 byte: parça uzunluğu
        chunk_len = struct.unpack('!I', data[:4])[0]
        chunk = data[4:4+chunk_len]

    buffered.append(chunk)
    print(f"[<] Uygulama katmanı parçası alındı: {len(chunk)} bayt ({len(buffered)}/{expected_chunks})")

    # Tümü geldiyse birleştir, decrypt et, kaydet
    if len(buffered) == expected_chunks:
        encrypted = b''.join(buffered)
        try:
            decrypted = fernet.decrypt(encrypted)
        except Exception as e:
            print("[-] Decryption hatası:", e)
            return
        with open(OUTPUT_FILE, "wb") as out:
            out.write(decrypted)
        print(f"[+] Tüm veri çözüldü ve kaydedildi: {OUTPUT_FILE}")
        # Sonlandır
        exit(0)

print("[*] ip_receiver.py başlatıldı, UDP 12345 dinleniyor…")
sniff( iface="\\Device\\NPF_Loopback", filter="udp and port 12345", prn=handle_packet, store=False)
