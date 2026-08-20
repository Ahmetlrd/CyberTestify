#!/usr/bin/env bash
# (3b-ii) PİNLENEN yetkili hedef IP'sine worker-konteyner egress'i AÇ — DOCKER-USER'da (ufw değil).
# egress-harden-docker.sh'DEN SONRA çağrılır. IPv4 -> iptables, IPv6 -> ip6tables.
set -euo pipefail
IP="${1:?kullanım: allow-target.sh <pinlenen-hedef-ip>}"
# Çift savunma (orchestrator/targetGuard zaten pinliyor): yasak/özel aralık reddedilir.
case "$IP" in
  164.92.223.208|10.*|169.254.*|127.*|192.168.*) echo "REDDEDİLDİ: yasak/özel IPv4 ($IP)"; exit 1;;
  172.1[6-9].*|172.2[0-9].*|172.3[01].*) echo "REDDEDİLDİ: RFC1918 172.16/12 ($IP)"; exit 1;;
  ::1|fe80:*|fc00:*|fd*|ff*) echo "REDDEDİLDİ: yasak/özel IPv6 ($IP)"; exit 1;;
esac
if printf '%s' "$IP" | grep -q ':'; then
  ip6tables -I DOCKER-USER 1 -d "$IP" -j ACCEPT
  echo "hedef egress AÇILDI (ip6tables/DOCKER-USER): $IP"
else
  iptables -I DOCKER-USER 1 -d "$IP" -j ACCEPT
  echo "hedef egress AÇILDI (iptables/DOCKER-USER): $IP"
fi
