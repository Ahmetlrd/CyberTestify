#!/usr/bin/env bash
[ -n "$1" ] || { echo "kullanım: allow-target.sh <IP>"; exit 1; }
case "$1" in 164.92.223.208|10.110.*) echo "REDDEDİLDİ: CyberTestify/prod aralığı hedeflenemez"; exit 1;; esac
ufw allow out to "$1"; echo "hedef egress AÇILDI: $1 (iş bitince revoke-target.sh $1)"
