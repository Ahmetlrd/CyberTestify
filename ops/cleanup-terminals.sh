#!/usr/bin/env bash
# PentAGI tarama sonrasi terminal container'larini normalde KENDISI siler. Bu, artik
# kalirsa temizleyen guvenlik agidir. Cron ile gunluk (04:00 UTC).
set -euo pipefail
ids=$(docker ps -a --filter "name=pentagi-terminal" --filter "status=exited" -q; \
      docker ps -a --filter "name=pentagi-terminal" --filter "status=dead" -q)
[ -n "$ids" ] && echo "$ids" | xargs -r docker rm -f || echo "[cleanup] artik terminal yok."
