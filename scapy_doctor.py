# scapy_doctor.py
import sys
import os
import time

print("--- Scapy Doktor Script'i Başlatılıyor ---")
print(f"Python Sürümü: {sys.version}")
print(f"Çalışma Dizini: {os.getcwd()}")
print("-" * 30)
time.sleep(1)

try:
    print("ADIM 1: Scapy kütüphanesi yükleniyor...")
    # scapy.all'u import etmek, ağ bileşenlerini başlatır.
    # Eğer takılma burada olursa, sorun Scapy kurulumunun kendisindedir.
    from scapy.all import conf, srp, Ether, ARP, get_if_list
    print(">>> BAŞARILI: Scapy kütüphanesi yüklendi.")
    print("-" * 30)
    time.sleep(1)

    print("ADIM 2: Kullanılabilir ağ arayüzleri (interface) listeleniyor...")
    # Bu fonksiyon, Scapy'nin sistemdeki ağ kartlarını görüp göremediğini test eder.
    interfaces = get_if_list()
    print(f">>> Bulunan Arayüzler: {interfaces}")
    print("-" * 30)
    time.sleep(1)

    # Test edilecek arayüz ve IP adresi
    # IP olarak genellikle cevap vereceği garanti olan modemin/router'ın adresi kullanılır.
    test_iface = "Wi-Fi"
    test_ip = "192.168.1.1"  # Kendi modem/router IP adresinizle değiştirebilirsiniz

    print(f"ADIM 3: '{test_iface}' arayüzü üzerinden ARP paketi gönderilecek...")
    print("!!! DİKKAT: Eğer program bu satırdan sonra takılırsa, sorun %100")
    print("!!! Scapy, Npcap ve ağ sürücünüz arasındaki uyumsuzluktan kaynaklanıyordur.")
    print("!!! Gönderme işlemi başlatılıyor (verbose=True ile detaylı çıktı alınacak)...")
    
    # Bu, ip_sender'ın takıldığı yerin en basit halidir.
    # verbose=True parametresi, bize daha fazla bilgi vermesi için eklendi.
    answered, unanswered = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=test_ip),
        iface=test_iface,
        timeout=8,
        verbose=True  # Detaylı çıktıları AÇIK
    )

    print("\n>>> BAŞARILI: ARP gönderme fonksiyonu takılmadan tamamlandı.")
    print("-" * 30)
    
    print("Alınan Cevaplar:")
    if answered:
        answered.summary()
    else:
        print("Hiçbir cihazdan ARP cevabı alınamadı (bu bir sorun olmayabilir).")

except Exception as e:
    print("\n--- BEKLENMEYEN BİR HATA YAKALANDI! ---")
    import traceback
    traceback.print_exc()
    print("-" * 40)

finally:
    print("\n--- Test Tamamlandı ---")
    input("Programı kapatmak için Enter tuşuna basın...")