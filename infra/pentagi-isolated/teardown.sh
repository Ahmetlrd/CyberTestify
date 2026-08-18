#!/usr/bin/env bash
# İmha: droplet + firewall + VPC + SSH key kaydı (ephemeral model).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DO_TOKEN="$(grep -E '^DIGITAL_OCEAN_API_KEY=' "$HERE/../../backend/.env" | head -1 | cut -d= -f2- | tr -d '"'"'"' \r')"
API="https://api.digitalocean.com/v2"; auth=(-H "Authorization: Bearer $DO_TOKEN")
S="$HERE/state.json"; [ -f "$S" ] || { echo "state yok"; exit 1; }
D=$(jq -r '.droplet_id//empty' "$S"); F=$(jq -r '.firewall_id//empty' "$S"); V=$(jq -r '.vpc_id//empty' "$S"); K=$(jq -r '.ssh_key_id//empty' "$S")
[ -n "$D" ] && { echo "droplet $D siliniyor"; curl -s "${auth[@]}" -X DELETE "$API/droplets/$D" >/dev/null; }
sleep 8
[ -n "$F" ] && { echo "firewall $F siliniyor"; curl -s "${auth[@]}" -X DELETE "$API/firewalls/$F" >/dev/null; }
[ -n "$K" ] && { echo "ssh key $K siliniyor"; curl -s "${auth[@]}" -X DELETE "$API/account/keys/$K" >/dev/null; }
sleep 5
if [ -n "$V" ]; then
  echo "vpc $V siliniyor (droplet çıkışı için retry)"
  for i in 1 2 3 4 5 6; do
    RESP=$(curl -s "${auth[@]}" -X DELETE "$API/vpcs/$V"); MSG=$(echo "$RESP" | grep -o "default VPC" || true)
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "${auth[@]}" "$API/vpcs/$V")
    if [ "$CODE" = "404" ]; then echo "  vpc SİLİNDİ"; break; fi
    if echo "$RESP" | grep -qi "default VPC"; then echo "  vpc bölge-varsayılanı (silinemez) — boş+ücretsiz, bırakıldı"; break; fi
    echo "  vpc henüz silinemedi (retry $i)"; sleep 10
  done
fi
echo "teardown bitti"
