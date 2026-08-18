#!/usr/bin/env bash
[ -n "$1" ] || { echo "kullanım: revoke-target.sh <IP>"; exit 1; }
ufw delete allow out to "$1" 2>/dev/null; echo "hedef egress KAPANDI: $1"
