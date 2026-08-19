#!/usr/bin/env bash
# (3b-ii) Yetkili hedef egress iznini KALDIR (DOCKER-USER). İş bitiminde/teardown öncesi.
set -euo pipefail
IP="${1:?kullanım: revoke-target.sh <hedef-ip>}"
while iptables -C DOCKER-USER -d "$IP" -j ACCEPT 2>/dev/null; do
  iptables -D DOCKER-USER -d "$IP" -j ACCEPT
done
echo "hedef egress KAPATILDI (DOCKER-USER): $IP"
