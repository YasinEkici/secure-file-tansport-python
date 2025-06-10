# client.py
#!/usr/bin/env python3

import socket
import sys
import os
import struct
from cryptography.fernet import Fernet

# --- Argüman kontrolü ---
if len(sys.argv) != 3:
    print("Kullanım: python client.py <Sunucu_IP> <Gönderilecek_Dosya>")
    sys.exit(1)

server_ip = sys.argv[1]
file_path = sys.argv[2]

if not os.path.isfile(file_path):
    print(f"Hata: '{file_path}' bulunamadı.")
    sys.exit(1)

# --- Sabitler ---
PASSWORD   = b"SuperSecretPassword123!"
KEY_FILE   = "key.key"
CHUNK_SIZE = 1400

# --- Anahtarı yükle ---
with open(KEY_FILE, "rb") as f:
    key = f.read()
fernet = Fernet(key)

# --- Dosyayı oku & şifrele ---
with open(file_path, "rb") as f:
    plaintext = f.read()
print(f"[+] Orijinal dosya boyutu: {len(plaintext)} bayt")

encrypted = fernet.encrypt(plaintext)
print(f"[+] Şifrelenmiş veri boyutu: {len(encrypted)} bayt")

# --- Parçalama ---
chunks = [encrypted[i:i+CHUNK_SIZE] for i in range(0, len(encrypted), CHUNK_SIZE)]
num_chunks = len(chunks)
print(f"[+] Toplam parça sayısı: {num_chunks}")

# --- Sunucuya bağlan & parola gönder ---
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    print(f"[+] {server_ip}:5001 adresine bağlanılıyor…")
    sock.connect((server_ip, 5001))

    # 1) Parolayı gönder
    sock.sendall(PASSWORD)
    print("[+] Parola gönderildi.")

    # 2) Parça sayısını gönder
    sock.sendall(struct.pack('!I', num_chunks))

    # 3) Her parçayı “[4 byte uzunluk][veri]” formatında gönder
    total_sent = 0
    for idx, chunk in enumerate(chunks, 1):
        sock.sendall(struct.pack('!I', len(chunk)))
        sock.sendall(chunk)
        total_sent += len(chunk)
        print(f"[>] Parça {idx}/{num_chunks} gönderildi ({len(chunk)} bayt)")

    print(f"[+] Gönderilen toplam şifreli bayt: {total_sent}")
    print("[*] Bağlantı kapatılıyor.")
