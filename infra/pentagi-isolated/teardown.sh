#!/usr/bin/env bash
# İmha: EPHEMERAL droplet (tek maliyet kaynağı). firewall/SSH-key/VPC REUSE için BIRAKILIR (stabil,
# ücretsiz; provision onları isimle reuse eder). ORPHAN-PROOF: state.json yoksa/yanlışsa droplet'i
# İSİMLE bulup imha eder → provision yarım bıraksa bile orphan kalmaz.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DO_TOKEN="${DIGITAL_OCEAN_API_KEY:-$(grep -E '^DIGITAL_OCEAN_API_KEY=' "$HERE/../../backend/.env" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"'"'"' \r')}"
[ -n "$DO_TOKEN" ] || { echo "token yok"; exit 1; }
API="https://api.digitalocean.com/v2"; auth=(-H "Authorization: Bearer $DO_TOKEN")
CURL=(curl -s --max-time 20)  # (D-hardening) DO API curl çağrıları KESİN timeout'lu — asılıp teardown'u bloklamasın
NAME="pentagi-isolated-fra1"
S="$HERE/state.json"

# 1) state.json'daki droplet (varsa)
D=""; [ -f "$S" ] && D="$(jq -r '.droplet_id//empty' "$S" 2>/dev/null)"
if [ -n "$D" ]; then echo "droplet $D (state) imha ediliyor"; "${CURL[@]}" "${auth[@]}" -X DELETE "$API/droplets/$D" >/dev/null; fi

# 2) İSİMLE orphan droplet(ler) — state eksik/yanlış olsa bile temizle (orphan-proof)
for OID in $("${CURL[@]}" "${auth[@]}" "$API/droplets?name=$NAME" | jq -r --arg n "$NAME" '.droplets[]|select(.name==$n)|.id' 2>/dev/null); do
  [ -n "$OID" ] && [ "$OID" != "null" ] && { echo "  isimle orphan droplet $OID imha ediliyor"; "${CURL[@]}" "${auth[@]}" -X DELETE "$API/droplets/$OID" >/dev/null; }
done

[ -f "$S" ] && rm -f "$S"
echo "teardown bitti (droplet imha; firewall/key/VPC reuse için bırakıldı — ücretsiz)"
