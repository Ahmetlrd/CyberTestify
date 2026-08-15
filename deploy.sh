#!/usr/bin/env bash
# CyberTestify — production deploy. Sunucuda /opt/cybertestify/app icinde calisir.
#   ./deploy.sh          -> aktif tarama varsa onay ister
#   ./deploy.sh --force  -> onay sormadan (aktif tarama olsa bile) devam eder
#
# Yaptigi: git pull (ui-ux) + docker compose build + up -d + prisma migrate deploy.
# NOT: PentAGI PII image'i AYRI bir akisla guncellenir (bkz PATCHES.md); bu script
# yalnizca CyberTestify uygulamasini gunceller.
set -euo pipefail

cd "$(dirname "$0")"
COMPOSE="docker compose -f docker-compose.prod.yml"
FORCE="${1:-}"

echo "==> Aktif tarama kontrolu"
RUNNING=$($COMPOSE exec -T cybertestify-db psql -U cyber -d cybertestify -tAc \
  "select count(*) from \"Flow\" where status='running';" 2>/dev/null | tr -d '[:space:]' || echo "?")
echo "    Calisan tarama (Flow.status='running'): ${RUNNING}"
if [ "$RUNNING" != "0" ] && [ "$RUNNING" != "" ]; then
  if [ "$FORCE" == "--force" ]; then
    echo "    UYARI: aktif tarama var ama --force verildi, devam ediliyor."
  elif [ -t 0 ]; then
    read -r -p "    Aktif tarama var. Deploy servisleri yeniden baslatabilir. Devam? [e/H] " ans
    [ "$ans" == "e" ] || { echo "Iptal edildi."; exit 1; }
  else
    echo "    HATA: aktif tarama var ve interaktif degil. --force ile calistirin." >&2
    exit 1
  fi
fi

echo "==> git pull (ui-ux)"
git pull --ff-only origin ui-ux

echo "==> docker compose build"
$COMPOSE build

echo "==> docker compose up -d"
$COMPOSE up -d

echo "==> prisma migrate deploy"
$COMPOSE exec -T api npx prisma migrate deploy

# (Tam Kapsamlı Pentest — FAZ B) test.cybertestify.com (OWASP Juice Shop) SABİT test hesabını
# yeniden garanti et. Juice Shop container recreate/reboot'ta DB'sini sıfırlar -> seed'li hesap
# silinir -> authenticated login e2e "bad_credentials" verir. Seed idempotent; başarısız olsa
# deploy'u BOZMAZ (|| true) — yalnız test fixture'ıdır, üretim akışını etkilemez.
echo "==> Juice Shop test hesabı seed (idempotent)"
$COMPOSE exec -T api npx tsx prisma/seedJuiceShopTestAccount.ts || echo "   (seed atlandı/başarısız — test fixture; üretimi etkilemez)"

# (CLARITY DEPLOY-PROOF REPLAY) Next.js her build'de /_next/static CSS/JS dosyalarına içerik-hash'li
# YENİ isim verir ve eskisini SİLER. Microsoft Clarity replay bu dosyaları URL'den yeniden çektiğinden,
# bir deploy'dan ÖNCE alınan kayıtlar deploy sonrası 404 → stilsiz görünür. Çözüm: her build'in
# static'ini birikimli bir arşivde topla ve çalışan container'a geri koy (eski+yeni hash'ler birlikte
# sunulur). 30 günden eski dosyalar temizlenir (Clarity saklama penceresiyle hizalı; arşiv şişmez).
echo "==> Clarity: eski static varlıklarını koru (deploy-proof replay)"
ARCHIVE=/opt/cybertestify/static-archive
mkdir -p "$ARCHIVE"
docker cp cybertestify-frontend:/app/.next/static/. "$ARCHIVE/" 2>/dev/null || true   # yeni build -> arşiv (additive)
find "$ARCHIVE" -type f -mtime +30 -delete 2>/dev/null || true                        # 30 günden eskiyi buda
docker cp "$ARCHIVE/." cybertestify-frontend:/app/.next/static/ 2>/dev/null || true   # arşiv (eski+yeni) -> container

echo "==> Durum"
$COMPOSE ps --format "table {{.Name}}\t{{.State}}\t{{.Status}}"
echo "==> Bitti."
