#!/usr/bin/env bash
# Container-egress default-DENY (DOCKER-USER zinciri; ufw değil — docker NAT ile kavga etmesin).
# İZOLASYON TABANI her zaman: allow docker-internal(172.16/12) + DNS; DROP CyberTestify prod
#   (164.92.223.208 + 10/8) + cloud-metadata(169.254/16); DROP rest.
# LLM: varsayılan olarak Anthropic:443 açılır. `--no-llm` -> Anthropic KAPALI (güvenli idle / reboot tabanı).
set -euo pipefail
NO_LLM=0; [ "${1:-}" = "--no-llm" ] && NO_LLM=1
CT_PUBLIC="164.92.223.208"
ANTHROPIC_HOST="api.anthropic.com"

iptables -F DOCKER-USER 2>/dev/null || true
iptables -A DOCKER-USER -j RETURN
# -I 1 ters sırada -> nihai sıra 1..N
iptables -I DOCKER-USER 1 -j DROP                                            # default-deny
if [ "$NO_LLM" -eq 0 ]; then
  AIPS=$(getent ahostsv4 "$ANTHROPIC_HOST" | awk '{print $1}' | sort -u)
  [ -n "$AIPS" ] || { echo "Anthropic çözülemedi"; exit 1; }
  for ip in $AIPS; do iptables -I DOCKER-USER 1 -p tcp -d "$ip" --dport 443 -j ACCEPT; done
fi
iptables -I DOCKER-USER 1 -p tcp --dport 53 -j ACCEPT
iptables -I DOCKER-USER 1 -p udp --dport 53 -j ACCEPT
iptables -I DOCKER-USER 1 -d 10.0.0.0/8      -j DROP
iptables -I DOCKER-USER 1 -d "$CT_PUBLIC"    -j DROP
iptables -I DOCKER-USER 1 -d 169.254.0.0/16  -j DROP
iptables -I DOCKER-USER 1 -d 172.16.0.0/12   -j ACCEPT
iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# reboot için snapshot (iptables-save)
mkdir -p /etc/pentagi
iptables-save > /etc/pentagi/iptables.rules 2>/dev/null || true

if [ "$NO_LLM" -eq 1 ]; then echo "== egress İZOLASYON TABANI (Anthropic KAPALI) uygulandı =="
else echo "== egress hardened (Anthropic AÇIK): $AIPS =="; fi
iptables -S DOCKER-USER
