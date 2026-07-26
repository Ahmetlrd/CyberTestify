# PentAGI PII Redaksiyon Yaması — Yeniden Üretilebilir Recipe

Bu dizin, PentAGI'ye uyguladığımız **PII (kişisel veri) redaksiyon** yamasını
**sıfır bir makinede yeniden üretilebilir** biçimde içerir. Amaç: tarama
içeriğindeki yapısal kişisel veri, veri Anthropic'e (ABD) gitmeden ÖNCE PentAGI
kaynağında maskelensin. (Ayrıntı: repo kökündeki `HANDOFF.md` → PII bölümü.)

## Hedef PentAGI sürümü

- **Tag/commit:** `v2.1.0` — `879e87c` (`git describe`: `v2.1.0-5-g879e87c`)
- Repo: https://github.com/vxcontrol/pentagi

> Farklı bir sürümde `wrapper.go` satır numaraları kayarsa `wrapper.go.patch`
> uygulanmayabilir; o durumda `README`'deki "Manuel uygulama" adımını izleyin
> (değişiklik yalnızca 2 küçük eklemedir).

## Dizin içeriği

- `pii_redaction.go` — eklenecek yeni dosya
  (`backend/pkg/providers/provider/pii_redaction.go`).
- `wrapper.go.patch` — `backend/pkg/providers/provider/wrapper.go` için git diff'i
  (iki choke point'e redaksiyon çağrısı ekler).
- `Dockerfile.cybertestify-pii` — resmi image'ı taban alıp yalnızca yamalı Go
  binary'sini üzerine koyan overlay build.

## Sıfırdan yeniden üretme (clean machine)

```bash
# 1) PentAGI'yi hedef sürümde klonla
git clone https://github.com/vxcontrol/pentagi.git
cd pentagi
git checkout 879e87c        # veya v2.1.0

# 2) Yamayı uygula
cp /path/to/pentagi-patch/pii_redaction.go backend/pkg/providers/provider/pii_redaction.go
git apply /path/to/pentagi-patch/wrapper.go.patch
cp /path/to/pentagi-patch/Dockerfile.cybertestify-pii backend/Dockerfile.cybertestify-pii

# 3) Yamalı image'i derle (overlay: resmi image + yamalı binary)
docker build -f backend/Dockerfile.cybertestify-pii -t cybertestify/pentagi:pii backend

# 4) Devreye al: PentAGI .env icinde
#    PENTAGI_IMAGE=cybertestify/pentagi:pii
#    ardindan: docker compose up -d
```

### Manuel uygulama (patch tutmazsa)

`wrapper.go` içinde iki fonksiyonun ilk satırına ekleyin:

- `WrapGenerateFromSinglePrompt(...)` gövdesinin başına:
  ```go
  prompt = RedactAll(prompt)
  ```
- `WrapGenerateContent(...)` gövdesinin başına:
  ```go
  messages = RedactMessages(messages)
  ```
Sonra `pii_redaction.go`'yu aynı pakete (`provider`) kopyalayın ve derleyin.

## Kalıntı risk (dürüstlük payı)

Redaksiyon **yapısal** PII'yi yakalar: email, TR telefon, TCKN (checksum),
kredi kartı (Luhn), IBAN (mod-97). Serbest metindeki **isim/adres** gibi verileri
YAKALAMAZ (regex sınırı, NER kapsam dışı). Bu bilinen ve kabul edilen sınırdır.

## Geri alma

PentAGI `.env`'de `PENTAGI_IMAGE=` satırını boşaltıp `docker compose up -d` →
resmi image'a döner.
