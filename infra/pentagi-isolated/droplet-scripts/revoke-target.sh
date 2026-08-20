#!/usr/bin/env bash
# (3b-ii) Pinlenen hedef egress iznini KALDIR (v4+v6). teardown droplet'i zaten imha eder; bu belt.
set -euo pipefail
IP="${1:?kullanım: revoke-target.sh <hedef-ip>}"
if printf '%s' "$IP" | grep -q ':'; then
  while ip6tables -C DOCKER-USER -d "$IP" -j ACCEPT 2>/dev/null; do ip6tables -D DOCKER-USER -d "$IP" -j ACCEPT; done
else
  while iptables -C DOCKER-USER -d "$IP" -j ACCEPT 2>/dev/null; do iptables -D DOCKER-USER -d "$IP" -j ACCEPT; done
fi
echo "hedef egress KAPATILDI: $IP"
