#!/usr/bin/env python3
"""
ip_sender.py — Scapy ile UDP port 12345 üzerinden
app-layer fragmentation + manuel TTL, flags, checksum.
"""

import sys
import os
import struct
from scapy.all import IP, UDP, Raw, send
from cryptography.fernet import Fernet

# --- Argüman kontrolü ---
if len(sys.argv) != 3:
    print("Kullanım: python ip_sender.py <Hedef_IP> <Gönderilecek_Dosya>")
    sys.exit(1)

dst_ip    = sys.argv[1]
file_path = sys.argv[2]

if not os.path.isfile(file_path):
    print(f"Hata: '{file_path}' bulunamadı.")
    sys.exit(1)

# --- Sabitler ---
PASSWORD   = b"SuperSecretPassword123!"
KEY_FILE   = "key.key"
CHUNK_SIZE = 1400
UDP_PORT   = 12345

# --- Fernet setup ---
with open(KEY_FILE, "rb") as kf:
    key = kf.read()
fernet = Fernet(key)

# --- Dosyayı oku & şifrele ---
with open(file_path, "rb") as f:
    plaintext = f.read()
encrypted = fernet.encrypt(plaintext)

# --- Application-layer fragmentasyon ---
chunks = [encrypted[i:i+CHUNK_SIZE] for i in range(0, len(encrypted), CHUNK_SIZE)]
num_chunks = len(chunks)
print(f"[+] Şifrelenmiş veri: {len(encrypted)} bayt, parçalar: {num_chunks}")

# --- Önce parola+parça sayısını UDP payload içine ekleyelim ---
# 1) payload = PASSWORD || struct(num_chunks) || chunk
for idx, chunk in enumerate(chunks, 1):
    # Application-header
    if idx == 1:
        header = PASSWORD + struct.pack('!I', num_chunks)
    else:
        header = PASSWORD + struct.pack('!I', len(chunk))
    payload = header + chunk

    # IP-level manipülasyon
    ip = IP(dst=dst_ip,
            ttl=64,                # Manuel TTL
            flags='MF' if idx < num_chunks else 0,  # MF bayrağı
            id=0x4242              # Sabit ID (tüm paketler aynı ID)
           )
    udp = UDP(sport=54321, dport=UDP_PORT)
    pkt = ip/udp/Raw(load=payload)

    # Manuel checksum devre dışı — Scapy otomatik hesaplar
    # Eğer elle setlemek isterseniz:
    # pkt[IP].chksum = scapy_checksum(raw(ip))  

    send(pkt, verbose=False)
    print(f"[>] Parça {idx}/{num_chunks} gönderildi: TTL={ip.ttl}, flags={ip.flags}, boyut={len(payload)}")

print("[*] ip_sender.py tamamlandı.")
