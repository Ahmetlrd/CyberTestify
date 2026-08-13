# CyberTestify — Yayın Hazırlık & Uyum Rehberi

> **Uyarı:** Bu doküman, üç ayrı araştırma (PentAGI+Anthropic lisans/izin, KVKK+TCK, TR e-ticaret+fatura) temel alınarak hazırlanmış bir **iç yol haritasıdır; hukuki mütalaa değildir.** Yayına almadan önce bir **avukat + mali müşavir (+ KVKK/DPO danışmanı)** onayı şarttır. İşaretler:
> **[KOD]** = yazılım/site teslimi · **[İŞ]** = şirket/kayıt/resmi işlem · **[HUKUK]** = avukat/DPO onayı gerektiren nokta
> **P0** = yayın öncesi zorunlu · **P1** = yayınla birlikte · **P2** = yayın sonrası/süreklilik

Son güncelleme: 2026-07-26 · Hukuki metin sürümü: `2026-07-26`

---

## 0. En yüksek riskli 4 nokta (özet)

1. **[HUKUK/İŞ] Yurt dışı veri aktarımı.** Her tarama Anthropic'e komut gönderir → rutin/sürekli aktarım. KVKK md.9 gereği **"veri sorumlusu→veri işleyen" standart sözleşmesi** + **5 iş günü Kurul bildirimi** gerekli. **Kısmen azaltıldı:** yapısal PII (email/telefon/TCKN/kart/IBAN) artık PentAGI kaynağında maskelenip öyle gidiyor (bkz HANDOFF.md PII bölümü); ama **isim/adres yakalanamıyor**, yani aktarım hâlâ kişisel veri içerebilir → standart sözleşme yine gerekli. Avukat bu kalıntı riski değerlendirmeli.
2. **[HUKUK/KOD] Paylaşımlı hosting / 3. taraf altyapı.** Alan adı sahipliği, o alan adının barındığı **sunucuyu** tarama yetkisi vermez. → **3 katmanlı kapsam kilidi UYGULANDI** (bkz. `HANDOFF.md` + [[scope-enforcement]]): Seviye 3 (worker log izleme→stopFlow), Seviye 2 (hosting tipi + ham-ağ paket kilidi), **Seviye 1 (egress proxy — terminaller yalnız aktif flow'un kapsamına çıkabilir, concurrency=1)**. Kalan hardening: `internal:true` bypass-proof izolasyon (HANDOFF'ta anlatıldı).
3. **[İŞ] PentAGI VXControl "Cloud Services" KAPALI tutulmalı.** AGPL/paid-service belirsizliği var. Yalnızca kendi Anthropic key'inle çalış; threat-intel/AI-support/premium Cloud bileşenlerini License Key olmadan kullanma.
4. **[İŞ] Şirket + ETBİS + e-Arşiv + iyzico** zinciri kurulmadan ticari satış yapılamaz (fatura + tüketici mevzuatı).

---

## 1. PentAGI + Anthropic (lisans & izinler)

**Durum:** Modelimiz (hizmeti/raporu satmak, yazılımı değil) hukuken uygun.

- ✅ **[KOD]** Müşteri PentAGI'ye/Anthropic'e hiç erişmiyor; yalnız şifreli rapor alıyor → "Services resale" değil, "product built on API" tarafında.
- ✅ **[KOD]** Her rapora AI-üretimi + doğruluk/bağımsız-teyit + "resmi test değildir" uyarısı eklendi (Anthropic Commercial Terms user-notice yükümlülüğü).
- 🔴 **[İŞ]** PentAGI'de **VXControl Cloud Services devre dışı** bırak (yalnız kendi Anthropic key). MIT/EULA bölgesinde kal.
- 🔴 **[İŞ]** PentAGI **NOTICE + MIT telif notunu** deployment'ta koru (silme).
- 🔴 **[İŞ]** Anthropic **Cyber Verification Program (CVP)** başvurusu yap — otonom pentest ajanı dual-use sınıflandırıcılara takılabilir; başvuru hem meşrulaştırır hem false-positive red'leri azaltır.
- 🟡 **[İŞ]** Taramaları **pasif** tut (mevcut politika) → Anthropic AUP'de açıkça izinli "sahibin rızasıyla zafiyet keşfi" alanında kal.
- ⚠️ **[HUKUK]** EULA (UK hukuku, web-UI ile kabul) ile MIT etkileşimi; "product vs resale" sınırı; raporların "consumer-facing/high-risk" sayılıp sayılmadığı (sayılırsa insan-onayı + AI-disclosure zorunlu olur, B2B'de büyük ölçüde muaf).

## 2. KVKK (6698) & TCK 243-245

- ✅ **[KOD]** **Aydınlatma Metni** yayında (`/legal/kvkk-aydinlatma`), açık rızadan **ayrı** sunuluyor.
- ✅ **[KOD]** Kayıt/tarama **sözleşmenin ifası** (md.5/2-c) temelinde — gereksiz açık rıza istenmiyor (Kurul görüşüne uygun).
- ✅ **[KOD]** Parola yalnız **bcrypt hash**; ham parola tutulmuyor/loglanmıyor.
- ✅ **[KOD]** **md.11 başvuru kanalı** (e-posta) aydınlatma metninde; 30 gün taahhüdü.
- ✅ **[KOD]** **Saklama/minimizasyon:** rapor içeriği 30 günde siliniyor (`REPORT_RETENTION_DAYS`), ham PentAGI verisi rapor üretilince siliniyor; **sipariş/ödeme kaydı korunuyor** (TTK/VUK).
- ✅ **[KOD]** **TCK 243 rızası:** doğrulanmış hostname + zaman damgalı + IP'li yetkilendirme onayı; "alan adı **ve altyapısı** sahibiyim" beyanı sipariş anında alınıp kaydediliyor.
- 🔴 **[HUKUK/İŞ]** **Anthropic standart sözleşmesi + 5 iş günü Kurul bildirimi** (bkz. §0.1).
- 🟡 **[KOD kısmen ✅]** **Prompt/veri minimizasyonu:** Anthropic'e giden mesajlardaki **yapısal PII** (email/TR-telefon/TCKN/kart/IBAN) PentAGI kaynağına yamalanan redaksiyonla (bkz `HANDOFF.md` + PentAGI `PATCHES.md`) veri ABD'ye gitmeden maskeleniyor; rapor bizim DB'ye de maskeli yazılıyor. **Kalıntı risk:** isim/adres gibi serbest-metin PII yakalanamıyor (regex sınırı) — avukatın md.9 değerlendirmesinde dikkate alınmalı. IP/log zaten Anthropic'e gitmiyor.
- ✅ **[KOD]** **Kapsam/RoE motoru (3 seviye + operasyonel sertleştirme):** Seviye 3 worker log izleme (yalnız istek-tarafı `args`, yanlış-pozitif düzeltildi)→stopFlow+audit; Seviye 2 hosting tipi + ham-ağ paket kilidi; Seviye 1 egress proxy (proaktif). Proxy sağlıksızsa tarama REDDEDİLİR (fail-closed), fail-fast config, networkLayer gate (`HARDENED_NETWORK_ISOLATION`), concurrency=1 (advisory lock + kısmi unique index), `[SCOPE-VIOLATION]` logları. **Canlı doğrulandı** (nomorelink.com: terminal `pentagi-egress`'te, tarama tamamlandı, proxy-kill reddi çalıştı). Bkz. `HANDOFF.md`. Kalan hardening: `internal:true` bypass-proof izolasyon (P2, networkLayer gate ile kilitli) + alerting (TODO).
- 🟡 **[İŞ/P2]** **VERBİS:** çalışan <50 **ve** bilanço <100M TL ise muaf (kümülatif). Her yıl eşik kontrol et. Muafiyet diğer KVKK yükümlülüklerini kaldırmaz.
- 🟡 **[İŞ/P2]** **Saklama & İmha Politikası** dokümanı; **veri ihlali müdahale planı** (72 saat bildirim pratiği).
- ⚠️ **[HUKUK]** Hostname'in kişisel veri sayılıp sayılmadığı (→ md.9 gerekli mi); meşru menfaat denge testi (IP/log); yetkilendirme metninin ceza hukuku yeterliliği.

## 3. TR E-Ticaret & Tüketici & Fatura

- ✅ **[KOD]** Zorunlu hukuki sayfalar (taslak): Kullanım Koşulları, KVKK Aydınlatma, Gizlilik, Çerez, **Mesafeli Satış Sözleşmesi**, **Ön Bilgilendirme Formu**, İptal/İade & **Cayma**, Sorumluluk Reddi — `/legal/*`, footer'dan erişilebilir.
- ✅ **[KOD]** **Cayma feragat** ayrı, önceden işaretsiz kutucukla alınıyor (md.15 dijital/anında ifa) + MSS/ÖBF onayı ayrı kutucuk; onaylar IP+sürüm+zaman damgalı kaydediliyor.
- ✅ **[KOD]** **Footer imprint** iskeleti (unvan/MERSİS/vergi/adres/iletişim/ETBİS karekod slotu) — `lib/company.ts`'ten okuyor.
- ✅ **[KOD]** Fiyatlar "tüm vergiler dahil" gösteriliyor.
- 🔴 **[İŞ/P0]** **Şirket kur** (şahıs veya Ltd.) → MERSİS + Vergi No üretir (sonraki her adımın ön koşulu).
- 🔴 **[İŞ/P0]** **ETBİS kaydı** (eticaret.gov.tr, ücretsiz) → **karekodu footer'a** ekle (zorunlu; `company.ts`'te `etbisRegistered`/karekod alanını doldur).
- 🔴 **[İŞ/P0]** **e-Arşiv (gerekiyorsa e-Fatura)** kurulumu — internet satışı olduğu için **her satışta e-Arşiv** varsay; mali mühür/entegratör.
- 🔴 **[İŞ/P0]** **iyzico üye işyeri** başvurusu (vergi levhası, IBAN, zorunlu sayfalar). *(Ödeme entegrasyonu senin isteğinle şimdilik sandbox/mock.)*
- 🔴 **[KOD/P0]** `lib/company.ts` içindeki `[köşeli parantez]` placeholder'ları **gerçek şirket bilgileriyle** doldur (unvan, MERSİS, vergi dairesi/no, adres, telefon, KEP).
- 🟡 **[KOD/P1]** Satın alma sonrası **sipariş/sözleşme onay e-postası** (kalıcı veri saklayıcısı — Yön. m.6).
- 🟡 **[KOD/P1]** iyzico ödeme başarılı → **otomatik e-Arşiv fatura** (entegratör API).
- ⚠️ **[HUKUK]** Cayma feragat metninin ve MSS/ÖBF içeriğinin yeterliliği; 2026 e-Arşiv/e-Fatura hadleri (GİB taslak — mali müşavirle teyit).

## 4. Teknik / Operasyonel Hazırlık

- ✅ **[KOD]** `helmet` güvenlik başlıkları + `express-rate-limit` (auth 20/15dk, genel API 100/15dk) + body limit + `trust proxy`.
- ✅ **[KOD]** Rapor AES-256-GCM şifreli; tek kullanımlık erişim kodu; ham veri purge.
- ✅ **[KOD]** DNS TXT doğrulaması taramadan önce zorunlu geçit (`isVerificationStillValid`).
- 🔴 **[İŞ/P0]** **Gerçek domain + Let's Encrypt TLS.** Şu anki self-signed + `NODE_TLS_REJECT_UNAUTHORIZED=0` **yalnız dev**; production'a ASLA taşınmaz.
- 🔴 **[İŞ/KOD/P1]** **Gerçek e-posta servisi** (SendGrid/Postmark/SES) + kendi domainin için **SPF/DKIM/DMARC** → erişim kodları spam'e düşmesin. (Şu an kod yalnızca dev'de gösteriyor.)
- 🟡 **[KOD/P1]** Erişim kodu kullanıldıktan sonra geçersizleştir (tek kullanım); rate-limit'i prod trafiğine göre kalibre et.
- 🟡 **[KOD/P2]** Kayıt için e-posta doğrulama / CAPTCHA (sahte hesap/otomasyon önleme — rate-limit üstüne).
- 🟡 **[İŞ/P2]** Loglama/izleme, yedekleme, ihlal müdahale runbook'u.

---

## 5. Öncelikli Go-Live Sırası (bağımlılık zinciri)

1. **[İŞ]** Şirket kur → MERSİS + Vergi No
2. **[İŞ]** ETBİS kaydı (+ karekod) · e-Arşiv kurulumu · iyzico üye işyeri
3. **[İŞ/HUKUK]** Anthropic standart sözleşme + Kurul bildirimi · CVP başvurusu · avukat/mali müşavir onayı
4. **[KOD]** `company.ts` gerçek bilgiler + ETBİS karekod footer'a · hukuki metinleri avukat onayıyla sonlandır
5. **[KOD]** Prompt minimizasyonu + kapsam/RoE motoru + kullanılınca geçersizleşen erişim kodu
6. **[İŞ/KOD]** Gerçek domain + Let's Encrypt · e-posta servisi + SPF/DKIM/DMARC
7. **[KOD]** (EN SON) UI/UX cilası + gerçek iyzico ödeme + e-Arşiv fatura entegrasyonu → yayın

---

## 6. Bu oturumda kod tarafında tamamlananlar (özet)

- helmet + rate-limit + body limit + trust proxy
- Rapor içeriği retention (30 gün) + sipariş kaydı korunur + ham veri purge
- Rapor disclaimer (AI + doğruluk + kapsam + "resmi değil")
- Rıza akışı: kayıtta ToS/KVKK; siparişte pentest yetki + MSS/ÖBF + cayma feragat — **IP + sürüm + zaman damgalı** kayıt (Customer.termsAccepted*, Order.ownershipConfirmedAt/distanceContractAcceptedAt/withdrawalWaivedAt/consentIp/consentVersion)
- 8 hukuki sayfa (`/legal/*`) + footer imprint + çerez banner
- `lib/company.ts` işletme bilgisi modülü (placeholder → doldurulacak)

## 6.1 Güncellemeler (2026-07-26) — durum ekranı + periyodik tarama

- ✅ **[KOD] Veri minimizasyonu (aktivite akışı):** Müşteriye ham PentAGI logu
  GÖSTERİLMEZ; yalnızca sabit, kategorilenmiş dostane cümleler + `redactAll()`
  invariant'ı. KVKK md.4 minimizasyon ilkesiyle uyumlu.
- 🔴 **[HUKUK/İŞ] Periyodik tarama — recurring billing YOK (bilerek):** Şu an
  **peşin N-tarama** modeli. Gerçek otomatik tekrarlayan ödeme eklendiğinde,
  Mesafeli Satış Sözleşmesi'ne **abonelik/otomatik yenileme** şartları (ön
  bilgilendirme, iptal, ücret iadesi) eklenmeli ve iyzico abonelik akışı + KVKK
  aydınlatması güncellenmeli. Bkz `HANDOFF.md`.
- 🟡 **[İŞ] E-posta bildirimleri** (doğrulama süresi doldu / zamanlanmış tarama
  durduruldu) şu an loglanıyor; gerçek e-posta servisi (SPF/DKIM/DMARC) eklenince
  bağlanacak.
- ✅ **[KOD] Dayanıklılık (watchdog):** Çökme/güç kesintisi/token bitmesi/ağ
  kesintisinde takılan tarama otomatik `scan_failed` yapılır ve kuyruk kilidi
  açılır (`services/watchdog.ts`). Müşteri "sonsuza kadar bekleyen" siparişte kalmaz.
- 🔴 **[HUKUK/İŞ] Başarısız taramada iade akışı YOK (bilerek):** Hizmet ifa
  edilemezse (watchdog `scan_failed`) müşteriye **otomatik iade uygulanmıyor** —
  şu an elle müdahale. Tüketici mevzuatı gereği ifa edilemeyen dijital hizmette
  bedel iadesi gerekebilir; gerçek ödeme entegrasyonuyla birlikte otomatik
  iade/retry politikası tanımlanmalı. Bkz `HANDOFF.md`.

## 6.2 Production altyapısı (2026-07-27)

- ✅ **[KOD/GÜVENLİK] İzolasyon:** PentAGI ve tüm iç servisler dışarıya kapalı
  (yalnız Caddy 80/443). Kapsam kilidi (egress-proxy) prod'da da api/worker'ın
  `service_healthy` bağımlılığı — proxy'siz sistem ayağa kalkmaz. TLS: Let's Encrypt.
- ✅ **[KVKK md.9 — yurt dışı aktarım] PII yaması canlıda:** Dışarıya veri
  gitmeden önce yapısal PII maskeleme yaması (`cybertestify/pentagi:pii`) production
  image'ında aktif (bkz `PATCHES.md`). Kalıntı risk (isim/adres) değişmedi.
- 🔴 **[SÜREÇ] Acceptance testleri (canlı tarama + kapsam-403 + PII):** gerçek
  Anthropic anahtarı prod'a girilince koşulacak (bkz `HANDOFF.md`); altyapı hazır,
  anahtar placeholder. "Yerelde geçti = prod'da geçer" varsayımı YAPILMADI.
- ✅ **[VERİ] Yedekleme:** her iki DB günlük pg_dump (7 gün). Sunucu-dışı (DO Spaces)
  kopyalama DO kimlik bilgisi gelince (TODO). Yedekler git'e YAZILMAZ.
- ✅ **[GÜVENLİK] Kapsam kilidi — Seviye-3 `monitor` (bilinçli karar):** Seviye-3
  (tool-args pattern tarama) `SCOPE_ENFORCEMENT=monitor` — audit/log amaçlı, otomatik
  durdurma yapmıyor. **Gerçek kapsam kilidi Seviye-1 egress-proxy'dir** (network
  seviyesinde engelleme, canlı testte kapsam-dışı hedefe **403** ile doğrulandı).
  Seviye-3'ün enforce'a alınmaması bilinçli: gerçek ajan çalışmalarında 3. parti
  script referansları (analytics/tracking) ve ajan reasoning metni nedeniyle yüksek
  yanlış-pozitif gözlemlendi, meşru taramaları gereksiz sonlandırıyordu. Bkz `HANDOFF.md`.
- ✅ **[SÜREÇ] Acceptance testleri canlıda GEÇTİ (2026-07-27):** kapsam-403,
  concurrency=1, PII redaksiyonu (yapısal PII → [X_REDACTED]), tam rapor üretim+teslim
  gerçek Anthropic anahtarıyla uçtan uca doğrulandı.

## 6.3 Güncellemeler (2026-08-02) — çok-dil + AI çözüm önerileri

- ✅ **[KOD/GÜVENLİK] AI Çözüm Önerileri yalnız remediation:** Eklenti içeriği promptta
  açıkça "istismar/exploit kodu YASAK, sadece düzeltme" kısıtıyla üretilir; ana rapordan
  ayrı, şifreli, ödeme yapılmadan API'den dönmez (kilitli).
- 🔴 **[HUKUK/İŞ] Ek-ödeme (fix-önerisi) tüketici bilgilendirmesi:** unlock şu an mock.
  Gerçek ek-ödeme eklendiğinde Mesafeli Satış / ön bilgilendirme akışına bu ek ürün de
  dahil edilmeli (fiyat, dijital-anında-ifa, cayma feragati). Fiyat PLACEHOLDER (Vedat onayı).
- 🟡 **[HUKUK] kvkk_hazirlik yalnız TR:** EN/global menüde gizli. GDPR/CCPA eşdeğer
  paketleri ayrıca, ilgili mevzuata özel yazılmalı (KVKK metni doğrudan çevrilemez).

## 7. Kaynaklar (araştırma çıktılarından)

- Anthropic AUP / Commercial Terms / CVP: anthropic.com/legal/aup · /legal/commercial-terms · support.claude.com (CVP)
- PentAGI LICENSE/EULA/NOTICE: github.com/vxcontrol/pentagi
- KVKK md.9/10/11, yurt dışı aktarım rehberi, VERBİS istisnaları: kvkk.gov.tr
- Mesafeli Sözleşmeler Yönetmeliği (m.5/m.6/m.15), ETBİS, e-Arşiv/e-Fatura hadleri: ticaret.gov.tr · gib.gov.tr
- TCK 243-245; sızma testi hukuki dayanağı (yazılı/doğrulanabilir rıza)
