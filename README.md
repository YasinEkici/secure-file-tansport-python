# Gelişmiş Güvenli Dosya Transfer Sistemi

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

Bu proje, standart ağ protokollerinin soyutlama katmanının altına inerek, düşük seviyeli IP paketi işleme, özel bir güvenilirlik katmanı ve modern güvenlik standartlarını bir araya getiren gelişmiş bir dosya transfer sistemidir. Sistem, Python ve Scapy kütüphanesi kullanılarak sıfırdan inşa edilmiştir.

---

## 📖 Proje Hakkında

Bu projenin temel amacı, bir dosya transfer sistemini en temel ağ prensipleri üzerine kurarak, ağın iç işleyişini uygulamalı olarak deneyimlemektir. Proje, güvenilirsiz bir protokol olan UDP üzerine, paket kayıplarına ve ağdaki bozulmalara karşı dirençli, ACK/NACK tabanlı özel bir güvenilirlik katmanı inşa eder. Aynı zamanda, standart TCP protokolü üzerinde de çalışabilen hibrit bir yapıya sahiptir. Tüm veri transferleri, AES şifrelemesi ve SHA-256 bütünlük doğrulaması ile güvence altına alınmıştır.

Proje, sadece bir dosya transfer aracı olmanın ötesinde, karşılaşılan platforma özgü ağ zorluklarına (örn: Windows'ta paket gönderimi, MAC adresi çözümlemesi) karşı geliştirilen mühendislik çözümlerini ve farklı protokollerin performans karakteristiklerini analiz eden kapsamlı bir test altyapısını da içermektedir.

## ✨ Temel Özellikler

* **Hibrit Protokol Mimarisi:** Ağ gecikmesine (RTT) göre otomatik olarak en verimli protokolü (TCP veya UDP) seçen akıllı bir yapı.
* **Düşük Seviyeli IP İşleme:** Scapy ile IP paket başlıklarının (TTL, Flags) manuel olarak oluşturulması ve manipüle edilmesi.
* **Özel Güvenilir UDP Protokolü:**
    * Paket kaybını tespit eden ve sadece eksik paketlerin yeniden gönderilmesini isteyen **ACK/NACK mekanizması**.
    * Büyük dosyalar için **manuel IP fragmentasyonu ve yeniden birleştirme**.
    * Ağdaki "hayalet paketlere" karşı protokolü sağlamlaştıran özel **`HASH` ve `DATA` etiketleri**.
* **Katmanlı Güvenlik:**
    * **AES-128 (Fernet)** ile uçtan uca veri şifreleme.
    * **SHA-256** ile dosya bütünlüğü doğrulaması.
    * **Önceden paylaşılan parola** ile temel kimlik doğrulama.
* **Gelişmiş GUI:** `tkinter` ile geliştirilmiş, donmayan (multi-threaded), gerçek zamanlı log ve ilerleme takibi sunan, alıcı/sunucu süreçlerini otomatik yöneten bir grafiksel kullanıcı arayüzü.
* **Otomatik Performans Analizi:** TCP, Ham UDP ve Güvenilir UDP modlarının hızlarını otomatize bir şekilde test eden, sonuçları metin ve grafik olarak sunan bir test script'i.
* **Sağlamlaştırılmış Ağ İletişimi:**
    * Windows'taki yönlendirme sorunlarını aşmak için Layer 2 seviyesinde `sendp` ile paket gönderimi.
    * Paket kayıplı ağlarda dahi MAC adresi bulabilen, tekrar denemeli özel ARP çözümleme fonksiyonu.

## 🛠️ Kullanılan Teknolojiler

* **Dil:** Python 3.10+
* **Düşük Seviyeli Ağ:** Scapy
* **Şifreleme:** Cryptography (Fernet)
* **GUI:** Tkinter
* **Grafik ve Analiz:** Matplotlib
* **Standart Ağ:** Socket

## ⚙️ Kurulum

Projeyi yerel makinenizde çalıştırmak için aşağıdaki adımları izleyin.

1.  **Projeyi Klonlayın:**
    ```bash
    git clone [https://github.com/kullanici-adiniz/proje-adi.git](https://github.com/kullanici-adiniz/proje-adi.git)
    cd proje-adi
    ```

2.  **Sanal Ortam Oluşturun (Önerilir):**
    ```bash
    python -m venv venv
    # Windows için:
    .\venv\Scripts\activate
    # macOS/Linux için:
    source venv/bin/activate
    ```

3.  **Gerekli Kütüphaneleri Yükleyin:**
    Proje dizininde `requirements.txt` adında bir dosya oluşturup içine aşağıdakileri ekleyin:
    ```txt
    scapy
    cryptography
    matplotlib
    ```
    Ardından yükleyin:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Şifreleme Anahtarını Üretin:**
    ```bash
    python generate_key.py
    ```
    Bu komut, projenin ana dizininde `key.key` adında bir anahtar dosyası oluşturacaktır.

5.  **Test Dosyası Oluşturun:**
    Performans ve dosya transferi testleri için `buyuk_dosya.bin` gibi büyük (10-50 MB) bir test dosyası oluşturun.

## 🚀 Kullanım

Sistemi kullanmanın en kolay yolu, tüm özellikleri bir araya getiren Grafiksel Kullanıcı Arayüzü'dür.

### Grafiksel Kullanıcı Arayüzü (GUI) ile Kullanım (Önerilen)

1.  **GUI'yi Başlatın:** Projeyi **Yönetici (Administrator) haklarıyla** açtığınız bir terminalde çalıştırın. Bu, arayüzün arkaplanda alıcı script'lerini başlatabilmesi için gereklidir.
    ```bash
    python gui.py
    ```
2.  **Bilgileri Doldurun:**
    * `Sunucu IP Adresi`: Testler için kendi makinenizin IP adresini (`192.168.x.x`) veya `127.0.0.1`'i girin.
    * `Şifre`: Belirlediğiniz bir parola girin.
    * `Ağ Arayüzü (UDP için)`: UDP modu için kullanılacak ağ kartının adını girin (örn: "Wi-Fi").
3.  **Alıcıyı Otomatik Başlat'ı İşaretleyin:** Yerel testler için bu kutucuğun işaretli olması, sizin yerinize alıcı script'ini otomatik olarak başlatıp sonlandıracaktır.
4.  **Dosya Seçin ve Gönderin:** "Dosya Seç" butonuyla bir dosya seçin, istediğiniz transfer modunu (UDP, TCP, Otomatik) işaretleyin ve "Gönder" butonuna basın. Logları ve ilerlemeyi arayüzden takip edebilirsiniz.

### Komut Satırı ile Gelişmiş Kullanım

#### Otomatik Test ve Analiz

Tüm performans benchmark testlerini tek bir komutla çalıştırmak, sonuçları analiz etmek ve performans grafiğini oluşturmak için:
```bash
# Yönetici olarak çalıştırılmış bir terminalde
python automated_tester.py
```

#### Manuel Transfer (Hibrit Kontrolcü ile)

`hybrid_main.py`, transferleri yönetmek için ana komut satırı aracıdır.

* **UDP Modunda Transfer:**
    ```bash
    python hybrid_main.py <HEDEF_IP> <DOSYA_ADI> -P <ŞİFRE> --mode udp --iface-udp "Wi-Fi"
    ```
* **TCP Modunda Transfer:**
    ```bash
    python hybrid_main.py <HEDEF_IP> <DOSYA_ADI> -P <ŞİFRE> --mode tcp
    ```
* **Otomatik Modda Transfer (RTT'ye Göre):**
    ```bash
    python hybrid_main.py <HEDEF_IP> <DOSYA_ADI> -P <ŞİFRE> --mode auto --iface-udp "Wi-Fi"
    ```

## 📂 Proje Dosya Yapısı

```
.
├── automated_tester.py     # Tüm performans testlerini otomatize eder ve raporlar.
├── client.py               # Güvenilir TCP gönderici modülü.
├── server.py               # Güvenilir TCP alıcı modülü.
├── ip_sender.py            # Düşük seviyeli UDP gönderici modülü (Scapy).
├── ip_receiver.py          # Düşük seviyeli UDP alıcı modülü (Scapy).
├── hybrid_main.py          # Mod seçimi yapan ve transferi başlatan ana kontrolcü.
├── gui.py                  # Tkinter tabanlı, çoklu-iş parçacıklı Grafiksel Kullanıcı Arayüzü.
├── generate_key.py         # AES/Fernet şifreleme anahtarı üretici.
├── key.key                 # Oluşturulan şifreleme anahtarı.
└── performance_graph.png   # Otomatik test sonucu oluşturulan grafik.
```

## Geliştirme Önerileri

* **Dinamik Tıkanıklık Kontrolü:** TCP'deki AIMD algoritmasına benzer bir mekanizma eklenerek UDP protokolünün ağ durumuna dinamik olarak uyum sağlaması.
* **Asimetrik Kriptografi:** Parola yerine, transfer başında bir Diffie-Hellman veya RSA anahtar değişimi ile oturum bazlı anahtarlar oluşturarak güvenliği artırmak.
* **GUI İyileştirmeleri:** Canlı hız göstergeleri, duraklatma/devam etme özelliği gibi ek fonksiyonlar eklemek.

## 📜 Lisans

Bu proje MIT Lisansı ile lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakınız.
