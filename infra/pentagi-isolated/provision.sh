#!/usr/bin/env bash
# AŞAMA 1 — İzole PentAGI droplet (fra1 + ayrı VPC + firewall). PentAGI KURMAZ.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DO_TOKEN="$(grep -E '^DIGITAL_OCEAN_API_KEY=' "$HERE/../../backend/.env" | head -1 | cut -d= -f2- | tr -d '"'"'"' \r')"
[ -n "$DO_TOKEN" ] || { echo "token yok"; exit 1; }
API="https://api.digitalocean.com/v2"
auth=(-H "Authorization: Bearer $DO_TOKEN" -H "Content-Type: application/json")
STATE="$HERE/state.json"
MYIP="${MYIP:-$(curl -s https://api.ipify.org)}"
NAME="pentagi-isolated-fra1"; VPC_NAME="pentagi-vpc-fra1"; FW_NAME="pentagi-fw"; KEY_NAME="pentagi-isolated-key"
BLOCK_IPS=("164.92.223.208" "10.110.0.0/16")   # CyberTestify prod public + AMS3 private (superset of /20)

echo "== 1) SSH anahtarı =="
KEYFILE="$HERE/id_pentagi"
[ -f "$KEYFILE" ] || ssh-keygen -t ed25519 -f "$KEYFILE" -N "" -C "pentagi-isolated" >/dev/null
PUB="$(cat "$KEYFILE.pub")"
# DO'da aynı isimli anahtar varsa onu kullan
KEY_ID="$(curl -s "${auth[@]}" "$API/account/keys" | jq -r --arg n "$KEY_NAME" '.ssh_keys[]|select(.name==$n)|.id' | head -1)"
if [ -z "$KEY_ID" ]; then
  KEY_ID="$(curl -s "${auth[@]}" -X POST "$API/account/keys" -d "$(jq -n --arg n "$KEY_NAME" --arg k "$PUB" '{name:$n,public_key:$k}')" | jq -r '.ssh_key.id')"
fi
FP="$(curl -s "${auth[@]}" "$API/account/keys/$KEY_ID" | jq -r '.ssh_key.fingerprint')"
echo "  ssh_key_id=$KEY_ID"

echo "== 2) VPC (fra1, ayrı) =="
VPC_ID="$(curl -s "${auth[@]}" "$API/vpcs" | jq -r --arg n "$VPC_NAME" '.vpcs[]|select(.name==$n)|.id' | head -1)"
if [ -z "$VPC_ID" ]; then
  VPC_ID="$(curl -s "${auth[@]}" -X POST "$API/vpcs" -d "$(jq -n --arg n "$VPC_NAME" '{name:$n,region:"fra1",ip_range:"10.200.0.0/24"}')" | jq -r '.vpc.id')"
fi
echo "  vpc_id=$VPC_ID (fra1)"

echo "== 3) cloud-init (host ufw: CyberTestify EGRESS BLOK + parola-SSH kapalı) =="
UD="$(cat <<'CI'
#cloud-config
package_update: true
packages: [ufw]
runcmd:
  - ufw --force reset
  - ufw default deny incoming
  - ufw default allow outgoing
  - ufw allow 22/tcp
  - ufw deny out to 164.92.223.208
  - ufw deny out to 10.110.0.0/16
  - ufw --force enable
  - sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
  - sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
  - systemctl restart ssh || systemctl restart sshd || true
  - echo "PENTAGI-ISOLATED-READY" > /root/isolation-ready.txt
CI
)"

echo "== 4) Droplet (fra1, VPC içinde, key-only) =="
DROP_ID="$(curl -s "${auth[@]}" "$API/droplets?name=$NAME" | jq -r --arg n "$NAME" '.droplets[]|select(.name==$n)|.id' | head -1)"
if [ -z "$DROP_ID" ]; then
  DROP_ID="$(curl -s "${auth[@]}" -X POST "$API/droplets" -d "$(jq -n --arg n "$NAME" --arg fp "$FP" --arg vpc "$VPC_ID" --arg ud "$UD" \
    '{name:$n,region:"fra1",size:"s-2vcpu-4gb",image:"ubuntu-22-04-x64",ssh_keys:[$fp],vpc_uuid:$vpc,user_data:$ud,ipv6:false,monitoring:false,tags:["pentagi-isolated"]}')" | jq -r '.droplet.id')"
fi
echo "  droplet_id=$DROP_ID"

echo "== 5) DO Cloud Firewall (inbound: yalnız SSH benim IP'imden; outbound: setup portları) =="
FW_ID="$(curl -s "${auth[@]}" "$API/firewalls" | jq -r --arg n "$FW_NAME" '.firewalls[]|select(.name==$n)|.id' | head -1)"
FW_BODY="$(jq -n --arg n "$FW_NAME" --arg ip "$MYIP" --argjson did "$DROP_ID" '{
  name:$n, droplet_ids:[$did],
  inbound_rules:[{protocol:"tcp",ports:"22",sources:{addresses:[($ip+"/32")]}}],
  outbound_rules:[
    {protocol:"udp",ports:"53",destinations:{addresses:["0.0.0.0/0","::/0"]}},
    {protocol:"tcp",ports:"53",destinations:{addresses:["0.0.0.0/0","::/0"]}},
    {protocol:"tcp",ports:"80",destinations:{addresses:["0.0.0.0/0","::/0"]}},
    {protocol:"tcp",ports:"443",destinations:{addresses:["0.0.0.0/0","::/0"]}}
  ]}')"
if [ -z "$FW_ID" ]; then
  FW_ID="$(curl -s "${auth[@]}" -X POST "$API/firewalls" -d "$FW_BODY" | jq -r '.firewall.id')"
else
  curl -s "${auth[@]}" -X PUT "$API/firewalls/$FW_ID" -d "$FW_BODY" >/dev/null
fi
echo "  firewall_id=$FW_ID (inbound SSH from $MYIP)"

# state kaydet (teardown için)
jq -n --arg d "$DROP_ID" --arg v "$VPC_ID" --arg f "$FW_ID" --arg k "$KEY_ID" --arg ip "$MYIP" \
  '{droplet_id:$d,vpc_id:$v,firewall_id:$f,ssh_key_id:$k,myip:$ip}' > "$STATE"
echo "state -> $STATE"

echo "== 6) Droplet aktif olana kadar bekle =="
for i in $(seq 1 40); do
  J="$(curl -s "${auth[@]}" "$API/droplets/$DROP_ID")"
  ST="$(echo "$J" | jq -r '.droplet.status')"
  PUBIP="$(echo "$J" | jq -r '.droplet.networks.v4[]?|select(.type=="public")|.ip_address')"
  PRIVIP="$(echo "$J" | jq -r '.droplet.networks.v4[]?|select(.type=="private")|.ip_address')"
  REG="$(echo "$J" | jq -r '.droplet.region.slug')"
  VPCU="$(echo "$J" | jq -r '.droplet.vpc_uuid')"
  echo "  [$i] status=$ST region=$REG pub=$PUBIP priv=$PRIVIP"
  [ "$ST" = "active" ] && [ -n "$PUBIP" ] && break
  sleep 8
done
jq --arg p "$PUBIP" --arg pr "$PRIVIP" --arg r "$REG" --arg vu "$VPCU" '. + {public_ip:$p,private_ip:$pr,region:$r,droplet_vpc:$vu}' "$STATE" > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"
echo "== DONE == public_ip=$PUBIP region=$REG vpc=$VPCU"
