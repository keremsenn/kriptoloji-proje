🔐 Kriptoloji Güvenli Sohbet (Hybrid Cryptosystem)
Bu proje, Android (Kotlin) ve Python (Flask-SocketIO) mimarisi üzerine kurulu, modern kriptografik algoritmaları kullanan uçtan uca güvenli bir haberleşme uygulamasıdır. Yazılım, hem asimetrik hem de simetrik şifreleme yöntemlerini birleştiren Hibrit Kriptosistem yapısını temel alır.

🚀 Öne Çıkan Özellikler
Dinamik El Sıkışma (Handshake): Kullanıcı, bağlantı aşamasında RSA veya ECC (ECDH) yöntemlerinden birini seçerek güvenli anahtar değişimini başlatabilir.

Hibrit Şifreleme: Anahtar değişimi asimetrik (RSA/ECC) algoritmalarla yapılırken, anlık mesajlaşma trafiği yüksek performanslı simetrik (AES/DES) algoritmalarla şifrelenir.

Kütüphaneli ve Manuel Mod: Algoritmaların çalışma mantığını gözlemlemek için standart kripto kütüphaneleri (PyCryptodome, javax.crypto) veya eğitim amaçlı manuel XOR implementasyonları arasında geçiş yapılabilir.

Gerçek Zamanlı İletişim: WebSocket (Flask-SocketIO) protokolü ile düşük gecikmeli veri iletimi sağlanır.

🛠 Teknik Mimari ve Algoritmalar
1. Anahtar Değişimi (Key Exchange)
RSA-2048: OAEP padding ve SHA-256 özet algoritması ile güvenli anahtar taşıma.

ECC (ECDH): secp256r1 eğrisi üzerinde Diffie-Hellman matematiği kullanılarak, ağ üzerinden anahtar geçmeden "Shared Secret" (Ortak Sır) türetme.

2. Mesaj Şifreleme (Data Encryption)
AES-128 (CBC Mode): Rastgele IV (Initialization Vector) kullanımı ile her mesaj için benzersiz şifreli çıktı.

DES: Geriye dönük uyumluluk ve performans testi için sunulan blok şifreleme seçeneği.

📱 Uygulama Arayüzü
Uygulama, Material Design 3 prensiplerine uygun olarak Jetpack Compose ile geliştirilmiştir:

Bağlantı Paneli: IP ve protokol ayarlarının yapıldığı alan.

Güvenlik Ayarları: Algoritma seçimi ve mod (Kütüphane/Manuel) anahtarı.

Sohbet Ekranı: Şifreleme süreçlerini (anahtar alındı, oturum kuruldu vb.) anlık olarak gösteren sistem logları ve mesajlaşma alanı.

💻 Kullanılan Teknolojiler
Android: Kotlin, Jetpack Compose, OkHttp, Coroutines, ViewModel.

Backend: Python, Flask, Flask-Sock (WebSocket), PyCryptodome, Cryptography.io.

Güvenlik: RSA, ECC (ECDH), AES, DES, SHA-256, MD5.
