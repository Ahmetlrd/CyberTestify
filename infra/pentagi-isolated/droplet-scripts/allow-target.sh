#!/usr/bin/env bash
# (3b-ii) Yetkili HEDEF IP'sine worker-konteyner egress'i AÇ — DOCKER-USER zincirinde (ufw değil;
# konteyner egress'i DOCKER-USER'dan geçer). egress-harden-docker.sh'DEN SONRA çağrılır.
set -euo pipefail
IP="${1:?kullanım: allow-target.sh <yetkili-hedef-ip>}"
# CyberTestify prod (public+VPC) + tüm 10/8 özel aralık hedeflenemez (çift savunma; orchestrator da guard'lar).
case "$IP" in 164.92.223.208|10.*|169.254.*|127.*|192.168.*) echo "REDDEDİLDİ: yasak/özel aralık ($IP)"; exit 1;; esac
iptables -I DOCKER-USER 1 -d "$IP" -j ACCEPT   # hedefe NEW izin — default DROP'tan önce
echo "hedef egress AÇILDI (DOCKER-USER): $IP  (iş bitince: revoke-target.sh $IP)"
