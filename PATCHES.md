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
