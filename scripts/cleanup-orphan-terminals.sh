#!/usr/bin/env bash
#
# GUVENLIK AGI (secondary cleanup) — orphan PentAGI terminal container temizligi.
#
# Birincil temizlik: worker/watchdog HER bitis yolunda pentagi.deleteFlow cagirir
# (terminal container'i yikar). Bu script o birincil temizlik BASARISIZ olursa
# (deleteFlow patladi, PentAGI o an cokuktu, process bitis-oncesi olduruldu vs.)
# devreye giren ikincil korumadir. Saatte bir cron ile calisir.
#
# GUVENLI ESIK: sistem concurrency=1 + 120 dk watchdog ile calisir; yani AKTIF bir
# taramanin terminal'i en fazla ~120 dk yasar. Bu yuzden ${MAX_AGE_SECONDS} (varsayilan
# 2 saat = 7200 sn) DAHA ESKI bir terminal container KESINLIKLE orphan'dir → guvenle
# kaldirilir. Boylece calisan bir taramayi ASLA olduremez.
#
# Kurulum (droplet, bir kez):
#   crontab -e  ->  0 * * * * /opt/cybertestify/app/scripts/cleanup-orphan-terminals.sh >> /var/log/orphan-cleanup.log 2>&1
#
set -euo pipefail

MAX_AGE_SECONDS="${ORPHAN_TERMINAL_MAX_AGE_SECONDS:-7200}"
NAME_PREFIX="pentagi-terminal-"
now="$(date +%s)"
removed=0

for c in $(docker ps --filter "name=${NAME_PREFIX}" --format '{{.Names}}'); do
  started="$(docker inspect -f '{{.State.StartedAt}}' "$c" 2>/dev/null || echo '')"
  [ -z "$started" ] && continue
  started_epoch="$(date -d "$started" +%s 2>/dev/null || echo 0)"
  [ "$started_epoch" -le 0 ] && continue
  age=$(( now - started_epoch ))
  if [ "$age" -gt "$MAX_AGE_SECONDS" ]; then
    echo "$(date -Is) [cleanup] orphan terminal '$c' (yas ${age}s > ${MAX_AGE_SECONDS}s) kaldiriliyor"
    docker rm -f "$c" >/dev/null 2>&1 && removed=$(( removed + 1 )) || echo "$(date -Is) [cleanup] UYARI: '$c' kaldirilamadi"
  fi
done

echo "$(date -Is) [cleanup] tamamlandi — ${removed} orphan terminal kaldirildi."
