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

echo "==> Durum"
$COMPOSE ps --format "table {{.Name}}\t{{.State}}\t{{.Status}}"
echo "==> Bitti."
