# generate_key.py
from cryptography.fernet import Fernet

# 32 baytlık gizli anahtar üret
key = Fernet.generate_key()
# key'i key.key dosyasına yaz
with open("key.key", "wb") as f:
    f.write(key)
print("[+] AES anahtarı oluşturuldu ve 'key.key' dosyasına kaydedildi.")
