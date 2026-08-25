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

## 🔁 İKİNCİ TUR (2026-08-25) — git doğrulama + surface/passiveExtras tamamlandı

**P1 GİT KURTARMA DOĞRULAMASI (bağımsız, temiz):** `git status` = "working tree clean"; `git stash list` = BOŞ; tüm /en faz commit'leri sırayla mevcut (a7287e9→…); backend+frontend `tsc --noEmit` TEMİZ; test dosyaları (piiRedaction/credentialRedaction) 2/2 PASS. **Hiçbir tutarsızlık/kayıp yok.**

**surfaceReports TAM İngilizce (commit ...):** CSP alanı + 48 fix-builder çağrısı + bundle combiner + unscannable = %100 EN. `classifyExposedFile` locale-farkında yapıldı (exposed-file "reason" Türkçe sızıntısı düzeltildi). Kanıt: EN surface = 0 TR-char, honesty framework ✓, TR/DE regresyon temiz.

**passiveExtras (Ek Pasif Kontroller) TAM İngilizce (commit ...):** 44 kontrol + STATUS_LABEL_EN + render chrome + runPassiveExtras/renderPassiveExtrasMarkdown locale + report.ts wiring. basit/header_leak/dns_email en extras bölümü artık temiz. Kanıt: EN passiveExtras = 0 TR-char.

**Kanıt (3 paket, EN + honesty + TR-regresyon):** basit/surface/recon → EN-markers ✓, TR/DE-leak 0, TR-regresyon markers ✓ + EN/DE-leak 0. Live: /tr "Basit Tarama", /de "Basis-Scan", /en 307→/tr (gizli).

## ⚠️ HÂLÂ YAPILMADI — DÜRÜST İŞARET

1. **`activeVerifyReports` + `activeVerifyEvidence` + `authenticatedReports` + 12 kanıt modülü — `en` YAPILMADI.** Aktif Doğrulama ve Tam Kapsamlı Pentest paketleri /en'de raporu HÂLÂ TÜRKÇE üretir (karışık değil — TR'ye tutarlı düşüş). **Neden:** ~2.600 satır, 121+ çift-dilli çağrı + kanıt-katmanı imza değişimi. Bu turda ajan yaklaşımı 3 kez başarısız oldu (2× git-disaster + 1× kural-dışı paralel alt-ajan doğurma; hepsi yakalanıp `git stash pop`/`git checkout` ile kurtarıldı, kalıcı kayıp YOK). Kalanı ELLE bitirmek, tek oturumda /tr-/de'yi (paylaşılan kod) kırma riski taşıdığından — güvenlik>hız ilkesi + "yarım bırakma" gereği — **bilerek dokunmadım**; TR'de tutarlı halde bıraktım. Sonraki turda tek-tek (sıralı, ajansız) bitirilmeli.
2. **P3 gerçek iyzico GBP test satın-alma:** Bu headless ortamdan GERÇEK kart/iyzico ödemesi YAPILAMAZ — 5 paketin gerçek satın-alma PDF'i ancak SEN (tarayıcı + kart, cookie region=en) ile alınabilir. Ben yerine rapor gövdelerini generator'dan üretip dil-sızıntısı + honesty-framework doğruladım (yukarı).
3. **GBP fiyatlar = PLACEHOLDER** (EUR×~0.86). Gerçek £ + `npm run seed`. Ara: `GBP_PER_EUR_PLACEHOLDER`.
4. **UK işletme bilgisi** (Companies Act 2006) BOŞ placeholder — senden.
5. **4 UK yasal taslak** avukat onayı bekliyor; onaylayınca `robots index:false` kaldır.
6. **VISIBLE_REGION_CODES'a 'en' EKLENMEDİ** — /en gizli (senin public-açma kararın).

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
