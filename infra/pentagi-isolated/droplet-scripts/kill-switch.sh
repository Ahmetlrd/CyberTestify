#!/usr/bin/env bash
echo "[KILL-SWITCH] $(date -u +%FT%TZ)"
docker ps -q --filter "label=pentagi-agent" | xargs -r docker stop
pkill -f 'pentagi|agent-run' 2>/dev/null || true
ufw default deny outgoing; ufw --force enable
echo "  ajan durduruldu + egress KESİLDİ (default deny outgoing)."
echo "$(date -u +%FT%TZ) KILL-SWITCH tetiklendi" >> /opt/pentagi-run/audit/audit.log
