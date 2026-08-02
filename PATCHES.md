# PATCHES.md — PentAGI PII yaması ve production image akışı

CyberTestify, PentAGI'yi **PII (kişisel veri) redaksiyon** yamasıyla self-host eder.
Yamanın yeniden-üretilebilir reçetesi: [`pentagi-patch/README.md`](pentagi-patch/README.md).

## Hedef sürüm
- PentAGI **`879e87c`** (`v2.1.0-5-g879e87c`) — repo: https://github.com/vxcontrol/pentagi
- Yamalı image tag: **`cybertestify/pentagi:pii`**

## Yamanın içeriği (özet)
1. `pentagi-patch/pii_redaction.go` → `backend/pkg/providers/provider/pii_redaction.go`
2. `pentagi-patch/wrapper.go.patch` → `wrapper.go` içinde iki choke-point'e redaksiyon
   çağrısı (`RedactAll(prompt)`, `RedactMessages(messages)`) — LLM'e (Anthropic/ABD)
   veri gitmeden ÖNCE yapısal PII maskelenir.
3. `pentagi-patch/Dockerfile.cybertestify-pii` → resmi image'ı taban alıp yalnızca
   yamalı Go binary'sini overlay eder.

## Production'da image derleme (şu anki akış — sunucuda derleme)
Sunucuda (`/opt/cybertestify/pentagi`, 879e87c checkout + yama uygulanmış):
```bash
docker build -f backend/Dockerfile.cybertestify-pii -t cybertestify/pentagi:pii backend
# PentAGI .env: PENTAGI_IMAGE=cybertestify/pentagi:pii  → docker compose up -d
```
Devrede olduğunu doğrulama: `wrapper.go` içinde `RedactAll`/`RedactMessages` satırları
(sırasıyla ~129 ve ~260) bulunmalı.

## TODO — DigitalOcean Container Registry akışı (BİLEREK ERTELENDİ)
Şu an image **production sunucusunda derleniyor** (registry yok). DO kimlik bilgileri
sağlandığında hedeflenen akış:
1. **Yerelde** yama uygula + derle + test et (yukarıdaki reçete).
2. `docker tag cybertestify/pentagi:pii registry.digitalocean.com/<registry>/pentagi:pii`
3. `doctl registry login` + `docker push registry.digitalocean.com/<registry>/pentagi:pii`
4. Production `.env`: `PENTAGI_IMAGE=registry.digitalocean.com/<registry>/pentagi:pii`
5. Sunucuda: `doctl registry login && docker compose -f docker-compose.prod.yml pull pentagi && ... up -d`

Bu, production sunucusunda Go derlemesi yapma ihtiyacını kaldırır (hazır image çekilir).
Gerekli: DO API token (`doctl auth init`) + oluşturulmuş bir Container Registry.

---

## GET-only tool-level enforcement — UYGULANDI (2026-08-02)

**Uygulama (PII yamasi sablonuyla):**
- Yeni dosya: `pentagi-patch/passive_guard.go` → PentAGI kaynagi
  `backend/pkg/tools/passive_guard.go`. `IsWriteHTTPCommand(cmd)` — shell komutunda
  veri-degistiren HTTP metodu (curl -X/-d/-F, wget --post-data, python requests.post,
  ham HTTP istek satiri) tespit eder. `PENTAGI_GET_ONLY=false` ile kapatilabilir (vars. acik).
- Hook: `backend/pkg/tools/terminal.go` → `ExecCommand` GIRISINE eklendi (komut
  docker container'da CALISMADAN ONCE). Bloklanirsa ajana hata doner, komut HIC calismaz.
  Bu tek chokepoint TUM shell HTTP araclarini kapsar (transport-bagimsiz, HTTPS dahil).
  Manuel uygulama: `ExecCommand(... ) (string, error) {` acilisindan hemen sonra:
  \`\`\`go
  if blocked, match := IsWriteHTTPCommand(command); blocked {
      return "", fmt.Errorf("passive scan policy: data-modifying HTTP methods (POST/PUT/DELETE/PATCH) are blocked at tool level; use GET/HEAD/OPTIONS only (blocked: %q)", match)
  }
  \`\`\`
- Dogrulama: `pentagi-patch/passive_guard_test.go` — izole `go test` GECTI (write-method
  bloklandi, GET/HEAD/'posts'-URL/nmap/dig izinli; gercek tarama ACMADAN). Image derlendi.
- **Defense-in-depth:** worker `findForbiddenMethods` strict-halt IKINCI KATMAN olarak
  KALIR (obfuscation'a karsi). egress-proxy 405 (duz HTTP) da durur.
- iso27001 + pci `available:true` yapildi (menuye geri dondu).

### Onceki plan (arsiv)

**Sorun:** Tüm paketler pasiftir (yalnız GET/HEAD/OPTIONS). Ancak canlı testte ajan,
prompt yasağına + "POST → tarama iptal" uyarısına **rağmen** POST deniyor (özellikle
iso27001/pci "API/auth testi" davranışıyla). Mevcut savunma **reaktif**:
- worker `findForbiddenMethods` tool-call args'ında POST görürse flow'u **durdurur**
  (her-zaman-enforce) — güvenli ama tarama raporsuz biter;
- egress-proxy düz-HTTP'de 405 döner ama **HTTPS CONNECT tünelinde method şifreli**,
  görünmez → oradan POST geçebilir (worker yakalar ama iş işten geçmiş olabilir).

Kapsam-kilidi dersinin aynısı: **prompt garanti değil, teknik/fiziksel engel gerekir.**

**Kalıcı çözüm (bu ayrı görev, PII yaması gibi ele alınacak):** ajanın POST'u
FİZİKSEL olarak yapamaması. Değerlendirilecek yaklaşımlar:
1. **PentAGI HTTP/terminal aracını yamala** (PII `wrapper.go.patch` şablonu):
   PentAGI kaynağında ajanın HTTP isteği attığı aracı/çalıştırıcıyı bul; yapılandırılmış
   bir HTTP tool ise method whitelist (GET/HEAD/OPTIONS) ekle → non-GET reddedilir.
   `backend/pkg/tools/...` içinde HTTP/terminal tool tanımına bakılmalı.
2. **Terminal image'ında `curl` shim** (DOCKER_DEFAULT_IMAGE_FOR_PENTEST):
   pasif paketler için, `-X POST|PUT|DELETE|PATCH` ve `-d/--data/-F/--form`
   bayraklarını reddeden bir curl wrapper içeren özel terminal image derle. Ajan
   hangi komutu yazarsa yazsın write-method fiziksel olarak engellenir.
   (Not: ajan curl yerine python/wget kullanabilir → shim tüm HTTP araçlarını
   kapsamalı ya da (1) tercih edilmeli.)
3. **HTTPS MITM proxy** (TLS terminasyonu ile method görünür olur) — TERCİH EDİLMEZ:
   sertifika yönetimi + pinning kırılması + karmaşıklık.

**Öneri:** (1) — PentAGI tool seviyesinde method whitelist (en temiz, tüm HTTP
araçlarını kapsar, transport-bağımsız). Efor: PentAGI kaynağına dalış + yeni bir
`cybertestify/pentagi:pii` benzeri katman + registry akışı.

**O zamana kadar:** iso27001 & pci `available:false` (menüde YOK, API'de reddedilir).
worker strict-halt **KALICI** (GET-only patch gelse bile defense-in-depth olarak durur).
GET-only patch doğrulandığında (mümkünse TEK test taramasıyla) iki paket tekrar açılır.
