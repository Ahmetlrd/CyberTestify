#!/usr/bin/env bash
# (3b-ii) İzole droplet üzerinde PentAGI kurulumu + API-token bootstrap (3a'da kanıtlanan dizi).
# Droplet'te root olarak çalışır. ANTHROPIC_API_KEY ENV'den gelir (sk-ant) ve DİSKE BIRAKILMAZ
# (compose override ile konteyner env'ine enjekte). Sonuç: /opt/pentagi-run/api_token + graphql_path.
# NOT: İlk CANLI koşuda uçtan uca doğrulanacak; DO/secret basılmaz.
set -euo pipefail
# ————————————————————————————————————————————————————————————————————————————————————
# LLM ANAHTARI — GÜVENLİK KRİTİK (iki-leak vektörü). Anahtar runner tarafından SSH-STDIN ile
# /opt/pentagi-run/llmkey'e (chmod 600) akıtıldı (izole, tek-kullanımlık droplet; teardown'da imha).
# Burada shell env'ine EXPORT edilir ki `docker compose` ${ANTHROPIC_API_KEY:?} onu okusun (OFF-DISK:
# değer PentAGI .env'ine YAZILMAZ). set +x: değer komut-tracing ile log'a/panele ASLA BASILMAZ.
# ————————————————————————————————————————————————————————————————————————————————————
set +x
if [ -z "${ANTHROPIC_API_KEY:-}" ] && [ -f /opt/pentagi-run/llmkey ]; then
  ANTHROPIC_API_KEY="$(cat /opt/pentagi-run/llmkey)"   # değer echo EDİLMEZ
fi
[ -n "${ANTHROPIC_API_KEY:-}" ] || { echo "HATA: ANTHROPIC_API_KEY bulunamadı (/opt/pentagi-run/llmkey)"; exit 1; }
export ANTHROPIC_API_KEY   # docker compose SHELL ENV'den okur (off-disk); değer basılmaz
PENTAGI_REF="${PENTAGI_REF:-v2.1.0}"
mkdir -p /opt/pentagi-run

# 0) APT ÇAKIŞMASINI ÖNLE (taze Ubuntu ilk-boot): (a) cloud-init/unattended-upgrades bitene kadar
# bekle, (b) TÜM apt çağrıları (get.docker.com dâhil) lock'u 180s beklesin — hemen fail etmesin.
echo "== ilk-boot otomasyonu (cloud-init/apt) bekleniyor =="
cloud-init status --wait >/dev/null 2>&1 || true
mkdir -p /etc/apt/apt.conf.d
echo 'DPkg::Lock::Timeout "180";' > /etc/apt/apt.conf.d/99lock-timeout
# Emniyet: hâlâ apt kilidi tutuluyorsa kısa bir süre daha bekle (unattended-upgrades geç bitebilir).
for i in $(seq 1 18); do
  if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; then
    echo "  apt kilidi tutuluyor, bekleniyor… ($i/18)"; sleep 10
  else break; fi
done

# 1) Docker + compose (provision cloud-init'te kurulmadıysa)
command -v docker >/dev/null || { curl -fsSL https://get.docker.com | sh; }

# 2) PentAGI kaynağı
if [ ! -d /opt/pentagi/.git ]; then
  git clone --depth 1 --branch "$PENTAGI_REF" https://github.com/vxcontrol/pentagi /opt/pentagi
fi
cd /opt/pentagi

# 3) .env: COOKIE_SIGNING_SALT (JWT bootstrap için sabit) + DOCKER_NETWORK + ANTHROPIC boş (off-disk)
[ -f .env ] || cp .env.example .env
grep -q '^COOKIE_SIGNING_SALT=' .env || echo "COOKIE_SIGNING_SALT=$(openssl rand -hex 16)" >> .env
sed -i "s|^COOKIE_SIGNING_SALT=.*|COOKIE_SIGNING_SALT=${COOKIE_SIGNING_SALT:-$(grep '^COOKIE_SIGNING_SALT=' .env | cut -d= -f2)}|" .env
sed -i "s|^DOCKER_NETWORK=.*|DOCKER_NETWORK=pentagi-network|" .env
sed -i "s|^ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=|" .env    # anahtar .env'e YAZILMAZ

# 4) Anahtar off-disk: compose override ile shell env'inden konteynere geç
cat > docker-compose.override.yml <<'YML'
services:
  pentagi:
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:?anahtar shell env ile verilmeli}
YML

# 5) Stack'i getir + pentest/terminal imajlarını önceden çek (egress-deny ÖNCESİ)
docker compose up -d pgvector scraper pentagi
docker pull vxcontrol/kali-linux >/dev/null 2>&1 &
docker pull debian:latest >/dev/null 2>&1 &
wait

# 5b) HAZIRLIK BEKLEME: compose up -d hemen döner; DB + GraphQL server DİNLEMEYE başlamadan bootstrap/
# createFlow bağlanamaz. Önce pgvector (INSERT için), sonra PentAGI GraphQL (8443) hazır olsun.
echo "== pgvector (DB) hazır bekleniyor =="
for i in $(seq 1 40); do docker exec pgvector pg_isready -U postgres >/dev/null 2>&1 && { echo "  DB hazır ($i)"; break; } || sleep 3; done
echo "== PentAGI GraphQL API (8443) hazır bekleniyor =="
for i in $(seq 1 60); do
  code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 https://localhost:8443/ 2>/dev/null || echo 000)"
  [ "$code" != "000" ] && { echo "  API dinliyor (http=$code, $i)"; break; } || sleep 3
done

# 6) API-token bootstrap (OAuth'suz): default admin (id=1) için api_tokens satırı + HS256 JWT
python3 - <<'PY'
import subprocess, hashlib, hmac, base64, json, time, os, secrets, urllib.request, ssl
def psql(sql): return subprocess.run(["docker","exec","pgvector","psql","-U","postgres","-d","pentagidb","-tAc",sql],capture_output=True,text=True).stdout.strip()
salt=""
for line in open("/opt/pentagi/.env"):
    if line.startswith("COOKIE_SIGNING_SALT="): salt=line.split("=",1)[1].strip()
assert salt, "COOKIE_SIGNING_SALT yok"
uid=1; rid=1; ttl=86400
uhash=psql("SELECT hash FROM users WHERE id=1;")
tid=secrets.token_hex(5)
psql(f"INSERT INTO api_tokens (token_id,user_id,role_id,name,ttl,status) VALUES ('{tid}',{uid},{rid},'orchestrator',{ttl},'active') ON CONFLICT DO NOTHING;")
password=("4c1e9cb77df7f9a58fcc5f52d40af685|"+salt+"|09784e190148d13d48885aa47cf8a297").encode()
key=hashlib.pbkdf2_hmac("sha512",password,("pentagi.jwt.signing|"+salt).encode(),210000,32)
b64=lambda x: base64.urlsafe_b64encode(x).rstrip(b"=")
now=int(time.time())
h=b64(json.dumps({"alg":"HS256","typ":"JWT"},separators=(",",":")).encode())
c=b64(json.dumps({"tid":tid,"rid":rid,"uid":uid,"uhash":uhash,"exp":now+ttl,"iat":now},separators=(",",":")).encode())
sig=b64(hmac.new(key,h+b"."+c,hashlib.sha256).digest())
tok=(h+b"."+c+b"."+sig).decode()
os.makedirs("/opt/pentagi-run",exist_ok=True)
open("/opt/pentagi-run/api_token","w").write(tok); os.chmod("/opt/pentagi-run/api_token",0o600)
open("/opt/pentagi-run/graphql_path","w").write("/api/v1/graphql")
print("API-TOKEN BOOTSTRAP OK (token diske yazıldı, ekrana basılmadı)")
PY
echo "setup-pentagi tamam."
