#!/usr/bin/env bash
# CyberTestify — tek komutla her seyi baslat (localhost / dev).
# Kullanim:  ./start.sh
# Durdurmak: bu terminalde Ctrl+C (backend + frontend birlikte durur).
#
# NOT: Docker Desktop'in ACIK olmasi gerekir (uygulamayi ac). PentAGI ve
# pgvector "unless-stopped" oldugu icin Docker acilinca zaten gelir; bu script
# yine de garantiye alir.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
PENTAGI_DIR="$HOME/Downloads/pentagi"

echo "▶ 1/3  Docker: ag + kendi DB + PentAGI…"
docker network create pentagi-egress >/dev/null 2>&1 || true
docker start cybertestify-db >/dev/null 2>&1 || true
if [ -f "$PENTAGI_DIR/docker-compose.yml" ]; then
  ( cd "$PENTAGI_DIR" && docker compose up -d >/dev/null 2>&1 ) || echo "  ! PentAGI baslatilamadi (Docker Desktop acik mi?)"
fi

echo "▶ 2/3  Backend: egress-proxy + api + worker (:4000, :8899)…"
( cd "$ROOT/backend" && npm run dev:all ) &
BACK_PID=$!

# frontend Ctrl+C ile kapatilinca backend grubunu da durdur
trap 'echo; echo "durduruluyor…"; kill "$BACK_PID" 2>/dev/null; pkill -P "$BACK_PID" 2>/dev/null; exit 0' INT TERM

echo "▶ 3/3  Frontend: web sitesi (:3000)…"
echo "   → Hazir olunca:  http://localhost:3000"
( cd "$ROOT/frontend" && npm run dev )

kill "$BACK_PID" 2>/dev/null || true
