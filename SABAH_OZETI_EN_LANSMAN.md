# /en (İngiltere / UK) Lansmanı — Gece Turu Sabah Özeti

**Tarih:** 2026-08-25 · **Branch:** ui-ux · **Durum:** /en HÂLÂ GİZLİ (`VISIBLE_REGION_CODES`'a `'en'` EKLENMEDİ — bu senin vereceğin ayrı karar).

> ⚠️ **GECE İÇİNDE BİR OLAY:** Paralel çalışan bir alt-ajan yanlışlıkla `git stash` çalıştırıp çalışma ağacını sildi. **Tam kurtarıldı** (`git stash pop`) — hiçbir iş kalıcı kaybolmadı, ama bu olay zaman kaybettirdi ve rapor generatorlarının bir kısmı yarım kaldı (aşağıda "Kısmi" bölümü). Ders: alt-ajanlara git komutu YASAK kuralı yeterli olmadı; ileride generator çevirilerini elle veya izole worktree'de yap.

---

## ✅ TAMAMLANAN (commit'li + deploy)

**Foundation (commit a7287e9):** `en` RegionCode (UK) eklendi — `regions.ts`: label 'United Kingdom', 🇬🇧, locale `en-GB` (£1,234.56 + dd/mm/yyyy), lang `en` (DICTS.en zaten us/ae'den vardı), currency GBP, paymentProvider iyzico, invoicingMethod uk_vat. `pricing.ts` GBP desteği, `payment/invoicing/zod-enum` + `blog-lang` + `middleware /en/blog + /en/legal` istisnaları. **P3:** Uyum Paketi + S1 /en'de gizli (compliance filter + otonom-red-team notFound).

**P1 (commit 84820f3):** sqli/idor İş Etkisi `en` → **"breach of UK GDPR / Data Protection Act 2018"** (KVKK/DSGVO değil). Sözlükte KVKK/VERBİS `en`'de de eleniyor. Teknik tespit/CWE/OWASP DEĞİŞMEDİ.

**P0 (commit 77fe59e, kurtarma sonrası):** Checkout (order/page) TAM İngilizce + **Cancellation Rights onayı — Consumer Contracts (Information, Cancellation and Additional Charges) Regulations 2013** (2-adımlı, açık feragat; TASLAK). Shell: verify/profile/login/register/hakkimizda/iletisim/dashboard + tüm dashboard bileşenleri (StatusTracker/ScopeCertificate/ScanFailedActions/InvoiceRequestForm/ScanRunningView/LiveScanPhases — hepsi en). intlComingSoon'a en dahil (iyzico+GBP ile satın alınabilir). Tarih/para en-GB.

**P0 Footer + P5 Blog (commit ...):** Footer İngilizce nav + UK legal linkleri. `/en/blog` boş "coming soon" (İngilizce), hreflang 3-yönlü (tr/de/en), admin blog'a `en` seçeneği.

**P7 Yasal (commit 77fe59e, untracked→commit):** 4 UK taslak sayfası — `/en/legal/{terms,privacy,cancellation,business-info}` + `EnLegalArticle` sarmalayıcı. `robots index:false`. **⚠️ HEPSİ TASLAK — avukat onayı ŞART.** Business-info alanları BOŞ placeholder (uydurulmadı).

**Emails (commit 165a342):** mailer.ts müşteri e-postaları İngilizce (sipariş onayı/tarama başladı/rapor hazır/giriş başarısız/iade/doğrulama/reset). Admin bildirimleri TR. fmtMoney en-GB.

**P2 rapor motoru (kısmen):**
- `basitReport` (demo paketi) — **TAM İngilizce, doğrulandı (EN temiz, TR/DE sızıntı yok).** ✅
- `reconReports` — **TAM İngilizce.** ✅
- `techEol` + `fixSuggestions` — TAM İngilizce (3-yönlü locale). ✅
- pdf.ts katmanı + findingTaxonomy + report.ts framing — İngilizce zaten vardı (us/ae'den) + UK GDPR uyarlaması.

---

## ⚠️ KISMİ / YAPILMADI (senin tarafında veya sonraki turda)

1. **`surfaceReports` (~%70 İngilizce, KARIŞIK):** SSL/TLS + header + DNS + CORS alanları İngilizce; **CSP alanı + fix-builder'lar hâlâ Türkçe/Almanca (48 çağrı).** bundle_surface raporu şu an KARIŞIK dilli. Tamamlanmalı.
2. **`activeVerifyReports` + `authenticatedReports` + 12 kanıt modülü + activeVerifyEvidence + passiveExtras:** `en` YAPILMADI — bu paketler (Aktif Doğrulama, Tam Kapsamlı Pentest) raporu hâlâ Türkçe üretir. Bunlar en karmaşık generatorlar; elle bitmeli (ajan git-stash olayından sonra riskli).
3. **GBP fiyatlar = PLACEHOLDER:** `pricing.ts GBP_CENTS` — EUR'dan ~0.86 oranıyla türetilmiş TAHMİNİ değerler. **Gerçek £ rakamlarını gir + `npm run seed` çalıştır.** Ara: `GBP_PER_EUR_PLACEHOLDER` / `PLACEHOLDER_KULLANICI_ONAYI_GEREKLI`.
4. **UK işletme bilgisi:** business-info sayfası + Impressum-benzeri alanlar BOŞ. Companies Act 2006 bilgisi (şirket adı/adres/no/VAT) senden.
5. **Yasal taslak onayı:** 4 UK sayfası avukata gösterilmeden yayına ALINMAMALI; onaylayınca `robots index:false` kaldır.
6. **Örnek raporlar (.en.md):** /de'de yaptığımız gibi İngilizce örnek rapor gövdeleri YAZILMADI (sampleReports şu an en için TR/DE'ye düşer). İsteğe bağlı.

---

## 🧪 TEST (senin doğrulaman)

Cookie `region=en` ile (VISIBLE'a eklenmediği için /en/* URL'leri /tr'ye redirect olur; cookie-driven kök sayfalar en render eder):
1. Ana sayfa (InstantScan hero) → İngilizce.
2. `/order` (checkout) → İngilizce + **Cancellation Rights onayı (Consumer Contracts 2013)** + iyzico + **GBP (£, PLACEHOLDER fiyat)**.
3. Test satın-alma → **basit_tarama** seç (demo, TAM İngilizce rapor). PDF İngilizce olmalı, TR/DE sızıntısı olmamalı.
4. Regresyon: `/tr` ve `/de` HİÇ değişmedi (her fazda kontrol edildi; TR generator smoke temiz).

**⚠️ bundle_surface / bundle_active_verify / bundle_full_pentest raporu test edersen KARIŞIK/Türkçe görürsün — yukarıdaki (1),(2) maddeleri.**

## KESİN SINIR (korundu)
- `/tr`, `/de` davranışı birebir aynı. · S1 + Uyum Paketi /en'de görünmez. · `VISIBLE_REGION_CODES = ['tr','de']` (en EKLENMEDİ). · Gerçek fiyat/işletme-bilgisi/hukuk-onayı uydurulmadı — placeholder + bu not.
