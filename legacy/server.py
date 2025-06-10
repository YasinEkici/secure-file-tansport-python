# server.py
#!/usr/bin/env python3

import socket
import struct
from cryptography.fernet import Fernet

# --- Sabitler ---
HOST        = '0.0.0.0'
PORT        = 5001
PASSWORD    = b"SuperSecretPassword123!"
KEY_FILE    = "key.key"
OUTPUT_FILE = "received_decrypted.bin"
CHUNK_SIZE  = 1400  # MTU'dan biraz düşük

# --- Yardımcı fonksiyon ---
def recvall(conn, n):
    """conn.recv ile tam olarak n bayt oku, hata verirse EOFError fırlat."""
    data = b''
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            raise EOFError("Bağlantı erken kapandı")
        data += packet
    return data

# --- Anahtarı yükle ---
with open(KEY_FILE, "rb") as f:
    key = f.read()
fernet = Fernet(key)

# --- Sunucu soketini hazırla ---
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
    server_sock.bind((HOST, PORT))
    server_sock.listen(1)
    print(f"[+] Sunucu başlatıldı: {HOST}:{PORT}")

    conn, addr = server_sock.accept()
    with conn:
        print(f"[+] Bağlantı: {addr}")

        # --- Parola doğrulama ---
        recv_pass = recvall(conn, len(PASSWORD))
        if recv_pass != PASSWORD:
            print("[-] Parola hatalı, bağlantı kapatılıyor.")
            conn.close()
            exit(1)
        print("[+] Parola doğrulandı.")

        # --- Fragmentation bilgisi oku ---
        num_chunks_bytes = recvall(conn, 4)
        num_chunks = struct.unpack('!I', num_chunks_bytes)[0]
        print(f"[+] Beklenen parça sayısı: {num_chunks}")

        # --- Tüm parçaları sırayla oku ---
        encrypted_data = b''
        for i in range(num_chunks):
            # Parça uzunluğunu oku
            chunk_len_bytes = recvall(conn, 4)
            chunk_len = struct.unpack('!I', chunk_len_bytes)[0]
            # Parçayı oku
            chunk = recvall(conn, chunk_len)
            encrypted_data += chunk
            print(f"[<] Parça {i+1}/{num_chunks} alındı ({chunk_len} bayt)")

        print(f"[+] Toplam şifreli veri: {len(encrypted_data)} bayt")

        # --- Şifreyi çöz ve kaydet ---
        try:
            decrypted = fernet.decrypt(encrypted_data)
        except Exception as e:
            print("[-] Decryption hatası:", e)
            exit(1)

        with open(OUTPUT_FILE, "wb") as out_f:
            out_f.write(decrypted)
        print(f"[+] Dosya çözüldü ve kaydedildi: {OUTPUT_FILE}")

    print("[*] Sunucu işlemi tamamlandı, kapanıyor.")
