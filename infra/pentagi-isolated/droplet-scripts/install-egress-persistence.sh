#!/usr/bin/env bash
# Droplet'te çalıştır: egress izolasyon tabanını reboot-kalıcı yap.
# Repo'dan da /opt/pentagi-run'dan da çalışır (kaynak==hedef ise kopyayı atlar).
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/pentagi-run
mkdir -p "$DEST"
for f in egress-harden-docker.sh; do
  if [ "$SRC/$f" != "$DEST/$f" ]; then install -m 0755 -T "$SRC/$f" "$DEST/$f"; fi
done
chmod 0755 "$DEST/egress-harden-docker.sh"
install -m 0644 -T "$SRC/pentagi-egress.service" /etc/systemd/system/pentagi-egress.service
systemctl daemon-reload
systemctl enable pentagi-egress.service
echo "== pentagi-egress.service kuruldu + enable (reboot sonrası izolasyon tabanı otomatik) =="
systemctl is-enabled pentagi-egress.service
