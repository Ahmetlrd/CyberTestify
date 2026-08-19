#!/usr/bin/env bash
# Container-egress default-DENY at the DOCKER-USER chain (docker-correct eşdeğeri
# of host egress-harden). Allowlist: docker-internal target island + DNS + Anthropic:443.
# Explicit DROP: CyberTestify prod (public+VPC) + cloud metadata. Everything else DROP.
set -euo pipefail
CT_PUBLIC="164.92.223.208"   # CyberTestify prod public IP
ANTHROPIC_HOST="api.anthropic.com"

# resolve Anthropic IPs (current)
AIPS=$(getent ahostsv4 "$ANTHROPIC_HOST" | awk '{print $1}' | sort -u)
[ -n "$AIPS" ] || { echo "Anthropic çözülemedi"; exit 1; }

# flush our prior rules (idempotent): remove existing then re-insert
iptables -F DOCKER-USER 2>/dev/null || true
# DOCKER-USER default footer
iptables -A DOCKER-USER -j RETURN

# insert in REVERSE so final order is 1..N (each -I 1 pushes to top)
iptables -I DOCKER-USER 1 -j DROP                                             # N: default deny
for ip in $AIPS; do
  iptables -I DOCKER-USER 1 -p tcp -d "$ip" --dport 443 -j ACCEPT            # Anthropic:443
done
iptables -I DOCKER-USER 1 -p tcp --dport 53 -j ACCEPT                        # DNS tcp
iptables -I DOCKER-USER 1 -p udp --dport 53 -j ACCEPT                        # DNS udp
iptables -I DOCKER-USER 1 -d 10.0.0.0/8      -j DROP                         # CyberTestify VPC + any 10.x
iptables -I DOCKER-USER 1 -d "$CT_PUBLIC"    -j DROP                         # CyberTestify prod public
iptables -I DOCKER-USER 1 -d 169.254.0.0/16  -j DROP                         # cloud metadata
iptables -I DOCKER-USER 1 -d 172.16.0.0/12   -j ACCEPT                       # docker-internal target island
iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "== DOCKER-USER egress default-deny UYGULANDI =="
echo "Anthropic izinli IP'ler:"; echo "$AIPS" | sed 's/^/  /'
iptables -S DOCKER-USER
