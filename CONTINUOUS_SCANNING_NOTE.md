# Continuous / Zamanlanmış Tarama — Tasarım Notu (Faz 3 #7)

**Bu bir NOT'tur; kod yazılmadı. Uygulama sonraki bir promptun konusu.**

Bu bir güvenlik-testi TÜRÜ değil, bir abonelik/zamanlama meselesidir.

## Mevcut altyapı (zaten var)
- **`ScheduledScan` modeli + `schedules.ts` route'u**: müşteri periyodik tarama kurar
  (packageKey, intervalDays≥7, prepaid `remainingRuns` N, `nextRunAt`, `active`).
- **Scheduler/cron**: worker tick'inde `runDueSchedules` benzeri mantık `nextRunAt`'i geçmiş
  aktif kayıtları bulur, NORMAL sipariş akışına (`enqueueOrStartScan`) sokar (aynı concurrency=1
  kuyruğu), `remainingRuns--`, `nextRunAt += intervalDays`. 0'da `active=false`.
- **Kredi sistemi (İş 2)**: `Customer.creditBalance` + `CreditTransaction` ledger + `spendCredits`.
- **Not:** active-light paketler ŞU AN zamanlanamaz (her tarama ayrı yetkilendirme beyanı ister;
  `schedules.ts` reddeder). Continuous, öncelikle PASİF paketler için anlamlı.

## Continuous nasıl oturur (öneri)
1. **Model:** Ayrı bir "continuous abonelik" yerine mevcut `ScheduledScan`'i genişletmek en ucuzu:
   `remainingRuns` yerine (veya yanında) `mode: 'prepaid_n' | 'subscription'` + `active` süresiz.
2. **Kredi entegrasyonu:** Her otomatik çalıştırmada, prepaid `remainingRuns` düşürmek yerine
   **hesap kredisinden** `creditsForPackagePrice(paket)` kadar düş (İş 2 `spendCredits`). Bakiye
   yetersizse: çalıştırma ATLANIR + kullanıcıya "bakiye yükleyin" bildirimi, abonelik pasifleşmez
   (grace) — böylece continuous = "krediniz oldukça periyodik tarar".
3. **Fiyatlandırma:** Bundle (İş 2) continuous'un doğal ödeme biçimi — kullanıcı 5/10'lu kredi
   paketi alır, continuous onları zamanla harcar. Ayrı bir aylık abonelik SKU'su da eklenebilir
   (recurring billing — İyzico/Paddle abonelik API'si; şu an YOK, PAYMENT_PROVIDERS.md'deki
   entegrasyondan sonra).
4. **Sıklık kuralı:** Mevcut `minScheduleIntervalDays` (≥7 gün) korunur (maliyet + concurrency=1
   yükü). Continuous "günlük" istenirse concurrency modeli gözden geçirilmeli.
5. **Değişiklik-farkında rapor (ileride):** Continuous'un asıl değeri "diff" — önceki taramaya göre
   YENİ bulguları vurgulamak. Rapor saklama + karşılaştırma katmanı gerekir (ayrı iş).

## Kabaca efor
- Mevcut `ScheduledScan` + kredi ile "krediyle continuous": **Küçük-Orta** (~2-3 gün).
- Gerçek aylık abonelik (recurring billing): **Orta** — önce PAYMENT_PROVIDERS.md entegrasyonu.
- Diff/değişiklik raporu: **Orta-Büyük** (ayrı iş).

**Sonuç:** Continuous için yeni bir güvenlik mekanizması gerekmiyor; mevcut ScheduledScan +
kredi sistemi %80'ini veriyor. Eksik olan: krediyle-otomatik-çalıştırma bağlaması + (opsiyonel)
recurring billing + (opsiyonel) diff raporu. Kod, ayrı promptta.
