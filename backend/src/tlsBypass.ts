// (GÜVENLİK TARAYICI TLS) Güvenlik-testi hedefleri sık sık BOZUK / expired / self-signed TLS sertifikası
// taşır — bu başlı başına bir BULGUDUR, tarama engeli değil. Prod worker/server ortamı
// NODE_TLS_REJECT_UNAUTHORIZED almadığından, bad-cert hedeflere yapılan global fetch() çağrıları
// "TypeError: fetch failed" ile düşüyordu → tüm aktif problar başarısız → rapor YANILTICI biçimde "temiz"
// çıkıyordu (ör. demo.testfire.net'in süresi dolmuş sertifikası). Dev scripti bunu zaten env ile yapıyordu;
// prod'da eksikti. Süreç başında erken set ederiz (import sırası: EN BAŞTA import edilmeli).
if (!process.env.NODE_TLS_REJECT_UNAUTHORIZED) {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}
