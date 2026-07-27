#!/usr/bin/env bash
# Gunluk yedek: her iki Postgres'in pg_dump'i. Sunucuda /opt/cybertestify/ops/
# altinda cron ile calisir (03:00 UTC). Su an yedek SUNUCU ICINDE tutulur.
# TODO(Spaces): DO kimlik bilgisi gelince rclone/s3cmd ile sunucu-DISINA kopyala.
set -euo pipefail
TS=$(date -u +%Y%m%d-%H%M%S)
DIR=/opt/cybertestify/backups
mkdir -p "$DIR"
docker exec cybertestify-db pg_dump -U cyber -d cybertestify | gzip > "$DIR/cybertestify-$TS.sql.gz"
docker exec pgvector       pg_dump -U pentagi -d pentagidb   | gzip > "$DIR/pentagi-$TS.sql.gz"
find "$DIR" -name "*.sql.gz" -mtime +7 -delete
echo "[backup] $TS tamam ($(ls -1 "$DIR"/*.sql.gz | wc -l) dosya)."
