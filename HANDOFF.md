# CyberTestify — Devir/Çalıştırma Notu (HANDOFF)

Bu dosya, projeyi çalıştırmak ve son eklenen **Seviye 1 egress kilidi**ni
anlamak için gereken pratik bilgileri içerir. Uyum/hukuk için `COMPLIANCE.md`,
mimari kararlar için kod içi yorumlara bakın.

## Çalıştırma (localhost / dev)

Portlar: backend `:4000`, frontend `:3000`, kendi Postgres `:5433` (Docker),
PentAGI `:8443` (Docker), **egress proxy `:8899`** (yeni).

```bash
# 1) Kendi Postgres + PentAGI zaten Docker'da çalışıyor.
# 2) İzole egress network'ü (bir kez):
docker network create pentagi-egress   # zaten varsa hata verir, önemsiz

# 3) Backend (3 process):
cd backend
npm run dev            # API (:4000)
npm run worker         # flow poller + kapsam izleme + kuyruk promote
npm run egress-proxy   # SEVIYE 1 filtreleyen egress proxy (:8899) — ZORUNLU

# 4) Frontend:
cd frontend && npm run dev   # :3000
```

> **ÖNEMLİ:** `egress-proxy` çalışmıyorsa, PentAGI terminal container'ları
> `PROXY_URL` üzerinden çıkış yapamaz ve taramalar başarısız olur. Backend
> `dev`/`worker` ile birlikte **her zaman** çalışmalı. (Prod'da 3'ü de servis
> olarak kalıcı çalıştırın.)

## Seviye 1 — Egress kilidi (proaktif kapsam kontrolü)

Amaç: PentAGI tarama container'larının internete çıkışını, o an aktif olan
**tek** flow'un kapsamıyla (doğrulanan hostname + `Domain.resolvedIps` +
referans allowlist + private/loopback) sınırlamak. Önceki katmanlar reaktifti
(tespit→durdur); bu katman isteği **baştan engeller**.

**Nasıl çalışıyor:**
1. `backend/src/egress-proxy/server.ts` — HTTP forward + CONNECT proxy (:8899).
   Her isteğin hedefini `services/scope.ts` (Seviye 3 ile AYNI kod) ile kontrol
   eder; kapsam dışıysa 403/tünel-kapat + backend'e audit yazar.
2. Aktif kapsamı backend'ten çeker: `GET /internal/active-scope` (secret'li,
   `x-internal-secret`). Backend bu endpoint'te o an `running` olan flow'un
   hostname+IP'lerini döndürür. Aktif tarama yoksa **fail-closed** (yalnız
   allowlist/private geçer).
3. Bloklar `POST /internal/scope-audit` ile `Flow.scopeViolationTarget`'a
   yazılır (Seviye 3 audit'iyle aynı alan).
4. PentAGI `.env` (kurulum: `~/Downloads/pentagi/`):
   - `PROXY_URL=http://host.docker.internal:8899`
   - `DOCKER_NETWORK=pentagi-egress`
   Değişiklik `docker compose up -d` ile uygulandı; `.env` yedeği
   `~/Downloads/pentagi/.env.bak-egress-*`.

**Env değişkenleri (backend):**
- `EGRESS_PROXY_PORT` (vars. 8899)
- `INTERNAL_API_SECRET` (vars. `dev-internal-secret-change-me` — **prod'da değiştir**)
- `BACKEND_INTERNAL_URL` (vars. `http://localhost:4000`)
- `SCOPE_ENFORCEMENT` = `enforce` | `monitor` (vars. enforce)
- `SCOPE_ALLOWLIST` (virgüllü; vars. CVE/NVD/github/paket aynaları)

## Concurrency = 1 (bilinçli kısıt)

**Aynı anda yalnızca TEK tarama `scan_running` olabilir.** Fazla siparişler
`scan_queued`'da bekler; worker her tick sonunda `promoteQueued` ile sıradaki
en eskiyi başlatır (FIFO).

**Neden:** Egress proxy'nin allowlist'i o an aktif olan tek flow'un kapsamıyla
eşleşir. Birden fazla flow aynı anda çalışırsa proxy tüm aktif hedeflerin
**birleşimine** izin vermek zorunda kalır → müşteriler arası (cross-tenant)
kapsam sızıntısı riski. Bu yüzden concurrency=1 bilinçli bir tercihtir.

**Vedat için pratik anlamı:** Aynı anda sadece bir müşterinin taraması çalışır;
yoğunlukta diğerleri otomatik sıraya girer ve öncekiler bitince başlar.

**Ne zaman kaldırılabilir:** Per-flow dinamik allowlist/izolasyon yazıldığında
(her terminal'in yalnız kendi flow'unun kapsamına çıkabildiği bir mimari — ör.
per-flow ayrı proxy örneği/network veya proxy'nin isteği başlatan flow'u
tanıması). O zamana kadar concurrency=1 kalır.

## Bilinen sınır / hardening yolu (bypass-proof izolasyon)

Şu anki kurulum **"yumuşak" izolasyondur**: `pentagi-egress` normal (internal
olmayan) bir bridge'dir → terminaller `PROXY_URL` üzerinden çıkar (tüm mevcut
paketler HTTP/TLS olduğu için gerçekten filtrelenir), ancak teorik olarak ham
soket ile proxy'yi baypas edip doğrudan çıkabilirler. Mevcut katalog tamamen
HTTP/uygulama katmanı olduğundan (ham ağ/port paketleri Seviye 2'de zaten
bloklu) bu pratikte riski büyük ölçüde kapatır.

**Tam (bypass-proof) izolasyon için sonraki adım:**
1. `pentagi-egress`'i `internal: true` yap (doğrudan egress'i kes).
2. Egress proxy'yi bu ağa bağlı bir **container** olarak çalıştır ve aynı anda
   dış ağa da bağla (dual-homed) → tek çıkış yolu proxy olur.
3. Proxy'yi `config.ts`'ten ayır (kendi env'ini okusun) ki container'da tam
   backend env'i gerekmesin. `services/scope.ts` importu korunur.
Bu, ham nmap/port taramaları eklenmeden önce yapılmalı.

## Kapsam kilidi kapanışı (2026-07-26) — operasyonel sertleştirme

Kapsam kilidi artık "unutulamaz/atlanamaz":

1. **Egress-proxy zorunlu, koda gömülü.** Proxy'de `/health` var. Backend ve
   worker açılışta proxy sağlığını kontrol edip loud loglar. En önemlisi:
   `enqueueOrStartScan` / `startScanForOrder` / `promoteQueued` proxy sağlıksızsa
   YENİ tarama başlatmayı REDDEDER (Order `scan_failed` + `[orchestrator][GUARD]`
   logu). Worker her tick'te de kontrol eder (tarama sırasında çökerse yakalar).
   `npm run dev:all` (concurrently) üçünü birlikte başlatır; prod için
   `backend/docker-compose.yml` egress-proxy'yi `restart: always` + `healthcheck`
   ile ayrı servis yapar, api/worker `depends_on: service_healthy` → **proxy'siz
   prod ayağa kalkamaz**.
2. **Fail-fast config:** `validateScopeLockConfig()` açılışta çağrılır;
   `INTERNAL_API_SECRET`/`EGRESS_PROXY_PORT`/URL'ler eksik/geçersizse process durur.
3. **networkLayer paket gate:** `HARDENED_NETWORK_ISOLATION=true` olmadan ham
   ağ/port paketi hiçbir yerde aktif olamaz — seed'de `active:false`, `/packages`
   listesinde gizli, order route + orchestrator'da reddedilir.
4. **[SCOPE-VIOLATION] logları:** ihlaller yüksek görünürlüklü, greplenebilir
   prefixle loglanır (worker + proxy audit). Gerçek alerting (email/Slack) için
   yer `TODO(alerting)` ile işaretli (bu görevde zorunlu değildi).
5. **Concurrency=1 yarış-güvenli:** `startScanForOrder` Postgres advisory lock
   (transaction) ile serileştirir + kısmi unique index (`Flow_single_running_idx`,
   `WHERE status='running'`) DB-level ikinci hat. İki eşzamanlı istek → ikincisi
   kuyruğa alınır.

**KRİTİK yanlış-pozitif düzeltmesi:** Seviye 3 (worker log izleme) önceden tool
`result`/terminal ÇIKTISINI de tarıyordu → taranan sayfanın içindeki 3. taraf
linkleri (googletagmanager, facebook vb.) kapsam dışı sanılıp **her gerçek site
taraması scope_violation ile ölüyordu**. Düzeltildi: Seviye 3 artık YALNIZCA
istek-tarafı sinyalini (`toolCallLogs.args` — ajanın istediği hedef) tarar; yanıt
gövdeleri gerçek egress kontrolüne (Seviye 1 proxy) bırakılır.

**Canlı doğrulama (nomorelink.com, basit_tarama):**
- Terminal `pentagi-terminal-9` gerçekten `pentagi-egress` ağında açıldı.
- Tarama normal tamamlandı, rapor üretildi, `scopeViolationTarget=null` (yanlış
  pozitif yok), proxy BLOCK=0 (ajan kapsamda kaldı).
- Proxy `kill` edilince yeni sipariş GERÇEKTEN reddedildi (`scan_failed` +
  GUARD logu); proxy geri gelince tarama normal çalıştı.

**Kod tarafında kapsam kilidiyle ilgili kalan AÇIK YOK.** Bilerek sonraya
bırakılan iki şey (ikisi de bu görevin kapsamı dışıydı, net olarak işaretli):
- **Bypass-proof tam izolasyon** (`internal:true` network + dual-homed container
  proxy) — şu an "yumuşak" izolasyon; ham ağ/port paketi eklenmeden önce
  yapılmalı (yukarıdaki "hardening yolu"). networkLayer gate bunu zaten kilitliyor.
- **Gerçek alerting** (email/Slack) — kod içinde `TODO(alerting)` ile işaretli.

## PII / veri minimizasyonu (2026-07-26)

Tarama sırasında toplanan hedef içeriğindeki **yapısal kişisel veri**, veri
Anthropic'e (ABD) gitmeden ÖNCE ve bizim DB'mize yazılmadan önce maskelenir.

**İki katman:**
1. **PentAGI kaynağında (asıl kritik — ABD aktarımı):** Anthropic çağrısını
   PentAGI'nin Go backend'i yapıyor; bizim Node backend'imiz o akışta değil.
   Bu yüzden redaksiyon PentAGI kaynağına yamalandı:
   `backend/pkg/providers/provider/pii_redaction.go` + `wrapper.go` içindeki iki
   evrensel choke point (`WrapGenerateContent` = ajan zinciri, tool sonuçları dahil;
   `WrapGenerateFromSinglePrompt` = tek prompt) — TÜM sağlayıcılar buradan geçer.
   Belge: `~/Downloads/pentagi/PATCHES.md`. **Devreye alma:** resmi image yerine
   yamalı image (`cybertestify/pentagi:pii`) — `.env`'de
   `PENTAGI_IMAGE=cybertestify/pentagi:pii` (aktif). Geri alma: bu satırı boşalt +
   `docker compose up -d`.
2. **Kendi tarafımızda:** `services/piiRedaction.ts`, `report.ts` içinde rapor
   şifreli DB'mize yazılmadan önce (`redactAll(renderReportMarkdown(...))`) —
   sızan ham PII bizde tam haliyle saklanmaz.

**DÜRÜSTLÜK PAYI — hangi PII engelleniyor, hangisi engellenMİYOR:**
- ✅ **Engellenen (yapısal):** e-posta, TR telefon (05xx/+90), **TCKN** (11 hane +
  resmi checksum), **kredi kartı** (13–19 hane + Luhn), **IBAN** (mod-97). Sahte
  format/checksum tutmayanlar maskelenmez (false-positive azaltma).
- ❌ **Engellenemeyen (bilinen kalıntı risk):** serbest metindeki **isim, adres**
  ve diğer yapısal-olmayan kişisel veriler. Regex/checksum tabanlı bir sistemin
  doğal sınırıdır; NER (isim tanıma) bilerek kapsam dışı bırakıldı. **Avukatın
  KVKK md.9 değerlendirmesinde bunu dikkate alması gerekir** — "tamamen minimize
  edildi" demek YANLIŞ olur; "yapısal PII maskelenir, isim/adres maskelenmez" doğru.

**Not:** Embedding yolu (`EMBEDDING_URL/PROVIDER`) kullanıcının .env'inde boş → pasif;
aktive edilirse o çıkışa da redaksiyon eklenmeli (henüz yok).

**Doğrulama:** TS birim testleri **24/24** (pozitif + negatif/checksum); rapor
pipeline'ı sahte PII'yi 5/5 türde maskeledi, ham sızıntı yok; patched image ile
gerçek nomorelink.com taraması tamamlandı + rapor üretildi (yama akışı bozmuyor).

## Çok-bölgeli altyapı (multi-region) — 2026-07-26

Site `tr / us / ae` bölgeleri için config-driven, genişleyebilir bir altyapıya
sahiptir. **Yeni bölge eklemek = tek dosyaya (`frontend/config/regions.ts`) bir
`RegionConfig` girişi** (gerekiyorsa i18n dili). `de` (Almanya) eklenerek bunun
gerçekten tek-dosya olduğu test edildi ve sonra kaldırıldı.

**Yapı:**
- **Routing:** `middleware.ts` (cookie > coğrafi header > Accept-Language > `tr`)
  `/` ve `/packages`'i `/{bölge}`'ye yönlendirir. Marketing sayfaları
  `app/[region]/` (landing, fiyat); uygulama akışı (login/order/dashboard/legal)
  bölge-bağımsız URL, bölgeyi `region` cookie'sinden okur.
- **i18n:** `config/i18n.ts` (tr→Türkçe, us/ae→İngilizce). RegionSelector (Nav)
  bölge/dili değiştirir, cookie'ye yazar.
- **Fiyat:** `PackagePricing` DB tablosu (bölge×paket) + `services/pricing.ts`
  (TR authoritative, US/AE **tahmini placeholder**). `GET /orders/packages?region=`
  ve `createOrder` bölgesel fiyat/para birimi döndürür. `Intl` ile biçimlenir.
- **Ödeme:** `services/payment/` — `PaymentProvider` interface + factory
  (`tr→iyzico`, `us/ae→stripe`). Hepsi **sandbox** (mockInitiate); gerçek iyzico
  ve stripe entegrasyonları İSKELET, ayrı görev.
- **Fatura:** `services/invoicing/` — `earsiv / us_receipt / uae_vat` iskeletleri
  (para birimine göre factory). Hiçbiri gerçek değil.
- **Hukuki matris:** `LegalArticle` bölge-farkında; yalnızca `legalReady` bölgede
  (tr) gerçek metin, diğerlerinde "hazırlanıyor" placeholder. Footer da böyle.

### DÜRÜSTLÜK PAYI — "altyapı hazır" ≠ "yayına hazır"

Bu TEKNİK bir hazırlıktır; **üç bölgede birden satışa hazır olmak anlamına
GELMEZ.** ABD ve BAE'de gerçekten müşteri kabul etmeden önce, Türkiye için
yapılan HER adımın o bölge için **ayrıca ve bağımsız** yapılması gerekir:
- **Hukuk:** bölgenin veri koruma mevzuatı (US: CCPA/CPRA; AE: PDPL — Federal
  Decree-Law No. 45/2021), tüketici/e-ticaret kuralları, sözleşme metinleri.
- **Vergi/fatura:** US eyalet satış vergisi (bir ABD mali müşaviriyle), AE KDV
  %5 + FTA fatura alanları; gerçek fatura entegrasyonu.
- **Ödeme:** stripe (veya AE için Telr/PayTabs/Network International) gerçek
  merchant sözleşmesi + entegrasyonu.
- **Bilişim suçları / kapsam-rıza çerçevesi:** her ülkenin kendi mevzuatı.
- **Fiyatlar:** US/AE tutarları şu an tahmini; gerçek pazar kalibrasyonu gerekir.

### Faz-2 TODO (bilerek ertelendi)
- **Arapça (RTL):** i18n `dir:'rtl'` altyapısı hazır; Arapça sözlük + RTL layout
  testi eklenmedi. Yeni bir dil (`ar`) + `dir:'rtl'` ile aktive edilecek.
- **`de` vb. yeni bölgeler:** config girişiyle çalışır ama gerçek içerik/hukuk
  yukarıdaki listeyi gerektirir.

## Tarama durumu ekranı + Periyodik tarama — 2026-07-26

### A) Aktivite akışı (ham log DEĞİL)
- Aşama göstergesi (`StatusTracker`) + opsiyonel **"Detayları göster"** paneli.
- `services/activityFeed.ts`: tool-call adı → DOSTANE kategori cümlesi; ham
  komut/çıktı ASLA gösterilmez. **Her satır `redactAll()`'dan geçer** (rapor
  üretimiyle aynı invariant). Feed yalnızca sabit kategori cümleleri ürettiği
  için ham PII zaten akışa girmez (defense-in-depth). Sahte % göstergesi YOK.
- `Flow.activityFeed` (JSON); worker `getScopeLogs`'u paylaşarak her tick üretir;
  `GET /orders/:id` döndürür; dashboard 5 sn'de bir polling yapar.

### B) Periyodik (zamanlanmış) tarama
- `ScheduledScan` tablosu; `Order.scheduledScanId` ile üretilen siparişler izlenir.
- **Motor:** `services/schedules.ts` → `runDueSchedules()` worker tick'inde çalışır.
  Zamanı gelen aktif kayıtlar için **NORMAL sipariş akışıyla** (`enqueueOrStartScan`)
  order açar → **concurrency=1 kuyruğuna girer** (ayrı yol açmaz, egress/kilit
  bozulmaz). Test edildi: aktif tarama varken tetiklenen zamanlanmış tarama
  `scan_queued`'a alındı, ikinci flow AÇILMADI.
- **İş kuralı:** min aralık **7 gün** (`MIN_SCHEDULE_INTERVAL_DAYS`) — haftalıktan sık yok.
- **Doğrulama tazeliği:** her tetiklemede `isVerificationStillValid` (30 gün);
  süresi dolmuşsa tarama BAŞLATILMAZ, kayıt `active=false` + müşteri bilgilendirilmeli
  (şu an loglanır; **e-posta TODO**). Test edildi: süresi dolmuş domain → pasif, order yok.
- **Güvenceler:** `MAX_ACTIVE_SCHEDULED_SCANS` (vars. 100) aşılırsa yeni kayıt 503;
  kuyruk `SCHEDULED_QUEUE_WARN_THRESHOLD` (20) aşılırsa worker loud uyarır; bir
  zamanlanmış tarama **3 ardarda başarısız** olursa `active=false` (sonsuz kuyruk
  meşgul etmesin). `failCount` worker'da izlenir.
- **İleri tarihli başlatma:** `/order`'da "Belirli bir tarihte başlat" (datetime) —
  tek atış da düzenli de gelecekte başlayabilir. `POST /schedules` `startAt` (ISO,
  gelecek olmalı) alır → `nextRunAt=startAt`. Tek seferlik (runs===1) taramada
  tekrar olmadığı için min-7-gün kuralı uygulanmaz (worker o tarihte tetikler).
- **Frontend:** `/order`'da "Düzenli tekrarla" (haftalık/2-hafta/aylık + peşin N) +
  "Başlangıç: hemen / belirli tarih" + `/schedules` liste/iptal ekranı.

### Dayanıklılık — WATCHDOG (kesinti/çökme/token-bitmesi)
Tek emniyet supabı: **`services/watchdog.ts` `reapStuckFlows()`** worker'ın her
tick'inde EN BAŞTA çalışır (PentAGI'ye ulaşılamasa bile — yalnızca DB'deki
`Flow.startedAt`'e bakar). Bir tarama `SCAN_TIMEOUT_MINUTES` (vars. 120) üzeri
'running' kaldıysa takılmış sayılır → flow `failed`, sipariş `scan_failed`,
**concurrency=1 slotu serbest** (kuyruk sonsuza kadar kilitlenmez); zamanlanmışsa
`failCount++`. Bu tek kontrol şu senaryoların HEPSİNİ kapsar — çünkü hepsi aynı
belirtiyle biter (flow 'running'da asılı kalır): **sunucu/PentAGI çökmesi, güç
kesintisi, Anthropic kredi/token bitmesi, ağ kesintisi/PentAGI'ye ulaşılamaması**.
Ayrıca **orphan rezervasyon** (`pentagiFlowId` hâlâ `reserving-...`, createFlow
tamamlanmadan process öldü) `RESERVATION_TIMEOUT_MINUTES` (vars. 3) eşikte hızlıca
temizlenir. Not: concurrency=1 partial-unique-index gereği aynı anda yalnızca TEK
running flow olabilir, dolayısıyla aynı anda tek takılı flow olur. Test:
`reapStuckFlows` — 3sa takılı flow → reaped+slot 0; orphan (5dk) → reaped; taze
flow → dokunulmadı (PASS).

### BİLEREK ERTELENEN (dürüstlük payı)
- **Gerçek otomatik tekrarlayan ödeme (recurring billing) YOK.** Şu an
  **peşin (prepaid) N-tarama** modeli: müşteri N tarama için baştan öder (sandbox'ta
  ücret alınmaz), N bitince kayıt kapanır. iyzico abonelik/tekrarlayan ödeme akışı
  ayrı, daha büyük bir görev.
- **E-posta bildirimleri** (TTL-süresi-doldu, 3-başarısızlık-durduruldu): şu an
  yalnızca loglanıyor; gerçek e-posta servisi bağlanınca `services/schedules.ts` ve
  `worker.ts` içindeki `TODO(email)` noktalarına eklenecek.
- **Başarısız/takılan taramada OTOMATİK iade veya yeniden-deneme YOK.** Watchdog
  takılan taramayı `scan_failed` yapıp slotu serbest bırakır ama bir kerelik sipariş
  için otomatik para iadesi (`refunded` durumu şemada var ama akış yok) ya da
  otomatik retry uygulanmıyor. Şu an operatörün elle müdahalesi gerekir. Zamanlanmış
  taramalarda 3-ardarda-başarısız → pasifleştirme kısmi güvence sağlar. Gerçek
  iade/retry politikası (ör. 1 otomatik retry, sonra iade) ayrı görev.

## PRODUCTION — DigitalOcean (2026-07-27)

**Sunucu:** DO Droplet, Frankfurt (FRA1), Ubuntu 22.04, 2 vCPU/4GB/80GB. Erişim:
sudo'lu `cybertestify` kullanıcısı (key-only). Root SSH girişi kapatıldı.
UFW: yalnız 22/80/443.

**Dizinler (sunucu):**
- `/opt/cybertestify/app` — bu repo (**ui-ux** dalı; deploy oradan).
- `/opt/cybertestify/pentagi` — PentAGI upstream `879e87c` + PII yaması + `pii` image.
- `/opt/cybertestify/ops` — `backup.sh`, `cleanup-terminals.sh`.
- `/opt/cybertestify/backups` — günlük pg_dump (7 gün).
- `.env` dosyaları yalnız sunucuda (`app/.env`, `pentagi/.env`) — **git'e yazılmaz.**

**Orkestrasyon:** `docker compose -f docker-compose.prod.yml up -d` TEK komut. `include`
ile PentAGI'nin kendi compose'u (pentagi/pgvector/scraper/pgexporter) + bizim stack
(cybertestify-db, egress-proxy, api, worker, frontend, caddy). Hepsi `restart: always`.
- **Ağ/izolasyon:** PentAGI ve tüm iç servisler DIŞARIYA KAPALI (yalnız 127.0.0.1 veya
  hiç yayınlanmamış). Dışarı yalnız Caddy 80/443. `api/worker` → `pentagi:8443` (iç,
  `SERVER_USE_SSL=false` düz http). egress-proxy `cybertestify`+`pentagi-egress` (dual-homed);
  api/worker ona `service_healthy` ile bağlı (proxy'siz kalkmaz). PentAGI terminal'leri
  `DOCKER_NETWORK=pentagi-egress` + `PROXY_URL=http://egress-proxy:8899`.
- **TLS:** Caddy + Let's Encrypt otomatik. `app.cybertestify.com`→frontend,
  `api.cybertestify.com`→api. `admin.` BİLEREK yok (PentAGI paneli yalnız SSH tüneli).

**Doğrulanan:** `https://api.cybertestify.com/health`={"ok":true} geçerli LE sertifikası;
`https://app.cybertestify.com`=200; paketler API'si seed'li fiyatlarla dönüyor; docker
restart sonrası 10 container healthy; yedek scripti iki dump üretti; do-agent aktif.

**Deploy:** `cd /opt/cybertestify/app && ./deploy.sh` (aktif tarama varsa onay ister;
`--force` ile atlar). git pull(ui-ux)+build+up+migrate.

### PROD'da BİLEREK ERTELENEN / Vedat'ın yapacakları
- 🔴 **ANTHROPIC_API_KEY** `pentagi/.env`'de `__SET_BY_VEDAT__` placeholder. Vedat:
  `ssh cybertestify@... "sudo sed -i s/__SET_BY_VEDAT__/GERÇEK_KEY/ /opt/cybertestify/pentagi/.env"`
  değil — dosyayı editleyip `docker compose -f docker-compose.prod.yml up -d pentagi`.
  Bu OLMADAN gerçek tarama, dolayısıyla **canlı tarama / PII / kapsam-403 / concurrency=1**
  acceptance testleri çalıştırılamadı → anahtar girilince koşulmalı.
- 🔴 **PENTAGI_SERVICE_TOKEN** `app/.env`'de placeholder. PentAGI admin panelinden
  (SSH tüneli: `ssh -L 8443:localhost:8443 cybertestify@...` → http://localhost:8443)
  bir API token üretilip `app/.env`'e yazılıp `... up -d api worker` gerekir.
- 🟡 **Embedding sağlayıcı:** PentAGI vektör belleği için embedding ister; Anthropic'in
  embedding API'si yok. Yalnız-Anthropic ile tam işlevsellik için ek bir embedding
  anahtarı (ör. OpenAI) gerekebilir — anahtar adımında netleşir.
- 🟡 **DO Container Registry** (bkz PATCHES.md) ve **Spaces'e sunucu-dışı yedek**
  (ops/backup.sh TODO) — DO kimlik bilgisi gelince.
- 🟡 **DO disk %80 alarmı** — do-agent aktif; alarm DO panelinden kurulmalı.
- 🟡 **GitHub deploy anahtarı:** şu an sunucuda Ahmetlrd'nin kişisel (yazma yetkili)
  anahtarı deploy key olarak duruyor. Repo-özel **salt-okunur deploy key** ile
  değiştirilmesi önerilir (GitHub → repo → Deploy keys).

## Kapsam kilidi — Seviye-3 `monitor` kararı (2026-07-27)
Seviye-3 (tool-args pattern tarama) **`SCOPE_ENFORCEMENT=monitor`** modunda çalışıyor
— **audit/log amaçlı, otomatik durdurma YAPMIYOR.** Gerçek kapsam kilidi **Seviye-1
egress-proxy**'dir (network seviyesinde engelleme, canlı testte kapsam-dışı hedefe
**403** ile doğrulandı). Seviye-3'ün `enforce` moduna alınmaması **bilinçli bir
karar**: gerçek ajan çalışmalarında 3. parti script referansları (analytics/tracking
scriptleri — ör. googletagmanager.com, facebook.net, clarity.ms) ve ajan reasoning
metni nedeniyle **yüksek yanlış-pozitif** oranı gözlemlendi, bu da meşru taramaları
gereksiz yere `scope_violation` ile sonlandırıyordu. Değiştirmek: sunucu `app/.env`
içinde `SCOPE_ENFORCEMENT=enforce` (önerilmez — bkz yukarıdaki gerekçe).

## Production hardening — uçtan uca canlı test bulguları (2026-07-27)
Gerçek tarama (createFlow → PentAGI → rapor) ile uçtan uca doğrulama sırasında
bulunup düzeltilenler:
- **Ağ:** `pentagi` orchestrator'ı LLM çağrısını `PROXY_URL=egress-proxy` üzerinden
  yapıyor ama `egress-proxy`'yi çözemiyordu → `createFlow` "lookup egress-proxy:
  server misbehaving" ile patlıyordu. Fix: egress-proxy `pentagi-network`'e de
  bağlandı. **`adacac5`**
- **Bug — scope extraction (yanlış-pozitif):** `extractTargets` URL host regex'i
  JSON-escaped `\n` gibi kaçışlarda durmuyor, `nomorelink.com\n\nrequired` gibi bozuk
  host çıkarıp **kapsam-İÇİ hedefi** ihlal sayıyordu → meşru tarama ölüyordu. Fix:
  host'u yalnız geçerli karakterlere (`[A-Za-z0-9.-]`) ayıkla. **`a6b90a0`**
- **Bug — enforce bypass:** worker'daki enforce-stop, `stopFlow` hatasını yutan bir
  `try/catch` içindeydi → `stopFlow` patlarsa ihlalli tarama yine tamamlanıp rapor
  üretiyordu. Fix: enforce eylemi try/catch DIŞINA alındı (stopFlow best-effort,
  sonraki tick'te tekrar dener). **`a6b90a0`**
- **Tuning — maxToolCalls:** `basit_tarama` 12 çok düşüktü; PentAGI overhead'i (docker
  seçimi, terminal init, screenshot, sayfa çekme) tavanı ajan bulgularını YAZMADAN
  tüketiyordu → her rapor boş/`incomplete`. 12 → 25; artık tam rapor üretiliyor. **`43ae5e6`**

**Doğrulanan (canlı):** kapsam-403, concurrency=1 (2. sipariş scan_queued), PII
redaksiyonu (email/telefon/TCKN/kart/IBAN → [X_REDACTED]), tam rapor üretim+teslim
(TLS/başlık/banner bulgularıyla, şifreli, accessSecret ile çözülüyor).

## İç yönetim paneli (admin) — 2026-07-27
**Müşteri sisteminden TAMAMEN AYRI.** Ayrı `AdminUser` tablosu, ayrı JWT secret
(`ADMIN_JWT_SECRET`), payload'ta `typ:'admin'`. Müşteri token'ı admin
endpoint'lerinde geçmez (canlı doğrulandı: müşteri JWT → 401, auth'suz → 401).

**Erişim:**
- Panel: **https://admin.cybertestify.com** (kök `/` → `/admin/login`). Aynı sayfalar
  `app.cybertestify.com/admin/*` altından da açılır (auth-guard'lı, güvenlik farkı yok).
- Admin API: `api.cybertestify.com/admin/*` (backend, ayrı auth). `POST /admin/auth/login`
  (register endpoint'i YOK). Veri uçları: `/admin/customers`, `/admin/orders`
  (status filtreli), `/admin/orders/:id`, `/admin/scope-violations`,
  `/admin/system-health`. Hepsi sayfalı (`?page&pageSize`, max 100).
- Rate limit: login sıkı (`authLimiter`, 15dk/20), veri uçları `apiLimiter` (dk/300).

**İlk admin oluşturma** (register YOK — yalnız CLI/DB):
```bash
docker exec -e ADMIN_EMAIL='vedat@...' -e ADMIN_PASSWORD='guclu-sifre-min-10' \
  cybertestify-api npx tsx prisma/createAdmin.ts
# veya argümanla:  ... createAdmin.ts vedat@... 'guclu-sifre'
```
Idempotent: aynı email varsa ŞİFREYİ günceller (şifre sıfırlama için de kullanılır).
`ADMIN_JWT_SECRET` sunucu `app/.env`'inde üretildi (JWT_SECRET'tan ayrı). **Şu an DB'de
0 admin var** — Vedat yukarıdaki komutla kendi hesabını oluşturmalı.

**IP allowlist (opsiyonel):** `app/.env`'de `ADMIN_IP_ALLOWLIST="1.2.3.4,5.6.7.8"` →
tüm `/admin/*` (login dahil) yalnız bu IP'lere açılır; sonra `up -d --force-recreate
api worker egress-proxy`. **Boş = kısıtlama yok** (Vedat sabit IP'sini bilmiyorsa boş
bırak). İstenirse Caddy'de de `admin.cybertestify.com` bloğuna `@ok remote_ip ...` +
`abort` eklenebilir (network seviyesi).

**2FA (TOTP) — TODO (bilerek ertelendi):** `AdminUser.totpSecret` alanı hazır ama
login'de ZORUNLU DEĞİL. Etkinleştirme: (1) `otplib` ekle, (2) admin başına secret
üret + QR ile enrollment (CLI/panel), (3) `routes/adminAuth.ts` login'inde
`admin.totpSecret` doluysa istekten gelen `totp` kodunu `authenticator.verify` ile
doğrula. Kod içinde `TODO(2FA)` işaretli.

## Rapor kalitesi — eksik/boş rapor kök nedeni ve çözümü (2026-08-02)
**Belirti:** `iso27001_hazirlik` raporu boş/`incomplete` geldi (canlı: flow 31 tool-call,
cap 30, hiç bulgu yazmadan kesildi). **Kök neden (iki katman):**
1. `maxToolCalls` tavanı düşüktü → ajan bulguları yazmadan kesiliyordu. Düzeltme:
   iso27001 30→**50**, kvkk 30→**45**, pci 40→**60**; tüm promptlara **BUDGET_GUARD**
   ("bütçe azalınca yeni keşif açma, ELİNDEKİ bulguyla raporu HEMEN yaz").
2. **Asıl derin neden:** `report.ts` yalnızca `tasks[].result`'a bakıyordu; bu alan
   ajan görevi DOĞAL tamamlarsa dolar, tavana çarpınca BOŞ kalır. Canlı logdan
   doğrulandı: PentAGI bulguları **`messageLogs type='report'/'done'`** mesajlarında
   da üretiyor. Düzeltme: `collectFindings()` — task.result yoksa report/done
   mesajlarına düşer. Böylece tavana çarpan tarama bile ELİNDEKİ bulguyla gelir;
   `incomplete` yalnızca TÜM kaynaklar boşsa true olur. Tavana çarpıp bulgu YAZILMIŞSA
   müşteri dashboard'da yine de tam rapor + (eksikse) şeffaf "eksik" uyarısı görür.

## Çok-dilli çıktı (locale) — 2026-08-02
- `Order.locale` (`tr`/`en`), bölgeden türetilir (tr→tr, us/ae→en). Ajana yanıt-dili
  talimatı (orchestrator), rapor şablonu tr/en (`report.ts` T sözlüğü).
- Paket adı/açıklaması EN i18n (`scanPackages.PACKAGE_I18N`). Fiyat/menü `?region` ile.
- 🔴 **`kvkk_hazirlik` EN/global menüde GİZLİ** (Türkiye'ye özel mevzuat). **TODO:**
  ileride **GDPR (AB)** ve/veya **CCPA (ABD)** için ayrı, o mevzuata özel eşdeğer
  paketler tanımlanmalı — `kvkk_hazirlik` şablonu örnek alınabilir ama madde
  eşlemeleri baştan yazılmalı.

## Ücretli eklenti: AI Çözüm Önerileri — 2026-08-02
- **Aynı flow'da** üretilir (ekstra LLM çağrısı/maliyet YOK): ajan bulgulardan sonra
  `===FIX_SUGGESTIONS===` delimiter'ı + her bulgu için remediation yazar. `report.ts`
  bunu ayırıp ANA rapordan AYRI, **aynı accessSecret ile** şifreler.
- **Kilit:** ödeme (unlock) yapılana kadar `POST /reports/:id/fix-suggestions/download`
  **402** döner (içerik sızmaz). `unlock` (şu an **MOCK/sandbox**) → `download` açılır.
  Dashboard'da kilitli kart + "Satın al ve aç" + indir.
- 🟡 **Fiyat PLACEHOLDER:** taban fiyatın **%50'si** (`fixSuggestionPrice`, paket
  bazında `ScanPackageDef.fixSuggestionPriceMinorUnit` ile override). **Vedat'ın kesin
  fiyatı onaylaması bekleniyor** — onaylanınca güncellenecek.
- 🔴 **TODO — gerçek ek-ödeme:** unlock şu an mock; gerçek iyzico ek-ödeme akışı
  (`reports.ts` içindeki `TODO(odeme)` + onay webhook'unda `fixSuggestionsUnlockedAt`)
  eklenmeli. Güvenlik: fix içeriği yalnız remediation — promptta istismar kodu YASAK.

## Yasak HTTP metodu — teknik engelleme (2026-08-02)
Tüm paketler PASİF (yalnız GET/HEAD/OPTIONS). Ajan POST/PUT/DELETE/PATCH denerse:
- **Worker (asıl enforce):** `scope.ts findForbiddenMethods` tool-call args'ında method
  tespit eder (curl -X/-d, "method":"POST", ham istek satırı; "post" kelimesi URL'de
  tetiklemez). Pasif pakette tespit → **HER ZAMAN ENFORCE** (SCOPE_ENFORCEMENT'tan
  bağımsız — method net sinyal, yanlış-pozitif yok): flow durdurulur, `scope_violation`,
  rapor üretilmez. **Canlı doğrulandı** (ajan POST denedi → 26. çağrıda durduruldu).
- **Egress-proxy (defense-in-depth):** düz HTTP'de GET/HEAD/OPTIONS dışı → **405**.
  NOT: HTTPS CONNECT tünelinde method şifreli/görünmez → orada asıl enforce worker'da.
- **Prompt:** POST yasağı SONUCUYLA güçlendirildi ("bir deneme taramayı raporsuz
  sonlandırır") → ajan denemekten caydırılır (savunma katmanı, garanti değil).

## Boş rapor + iç prompt dili (2026-08-02)
- **Somut bütçe eşiği:** orchestrator, `pkg.maxToolCalls`'a göre "~%55'inde keşfi bırak,
  raporu yaz" talimatı ekler ("yaklaşık yarı" göreceli ifadesi işe yaramıyordu).
- **İç promptlar artık HER ZAMAN İngilizce** (SAFETY/BUDGET/FIX/FOCUS + 7 paket gövdesi)
  — daha az token, daha tutarlı akıl yürütme. **İSTİSNA:** `kvkk_hazirlik` Türk hukuku
  terminolojisi için TÜRKÇE kalır. **Çeviri:** ayrı bir çeviri adımı EKLENMEDİ — ajana
  yanıt dili söylenir (orchestrator langLine), tr locale'de ajan çıktıyı DOĞRUDAN Türkçe
  yazar (çok-dilli; doğrulandı fluent). Gerekçe: ayrı LLM çeviri çağrısı backend'e
  Anthropic anahtarı + kırılgan runtime bağımlılığı eklerdi; in-flow çeviri capping
  riski taşırdı. Doğrudan-çıktı en ucuz + en sağlam.
- **Kalan kısıt:** iso27001 gibi paketlerde ajan bazen fix adımına ulaşamıyor
  (bütçe) → fix üretilmeyebilir; mekanizma sağlam, ajan-üretimi tuning konusu.

## Kapsam dışı (sıradaki görevler)
Gerçek iyzico/stripe ödeme + recurring billing + fix-önerisi ek-ödemesi, gerçek
e-Arşiv/US/AE fatura, US/AE + GDPR/CCPA hukuki metinler/paketler + fiyat
kalibrasyonu, e-posta servisi — hepsi ayrı görevler.
