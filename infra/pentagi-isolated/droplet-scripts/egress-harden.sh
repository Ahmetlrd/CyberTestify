#!/usr/bin/env bash
set -e
ufw --force reset >/dev/null
ufw default deny incoming; ufw default deny outgoing
ufw allow 22/tcp
# DNS (çözümleme)
ufw allow out 53
# Anthropic API (ajan LLM) — çözülen IP'ler /32
for ip in $(getent ahostsv4 api.anthropic.com | awk '{print $1}' | sort -u); do ufw allow out to "$ip" port 443 proto tcp; done
# loopback (localhost hedef) — ufw loopback'i varsayılan geçirir
ufw --force enable
echo "EGRESS DEFAULT-DENY etkin (yalnız DNS + Anthropic + loopback + SSH-in). CyberTestify ve her yer BLOKLU."
ufw status verbose | grep -iE "Default|443|53|22" | head
