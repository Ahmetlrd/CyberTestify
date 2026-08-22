#!/usr/bin/env bash
# (3b-ii) İzole droplet üzerinde PentAGI kurulumu + API-token bootstrap (3a'da kanıtlanan dizi).
# Droplet'te root olarak çalışır. ANTHROPIC_API_KEY ENV'den gelir (sk-ant) ve DİSKE BIRAKILMAZ
# (compose override ile konteyner env'ine enjekte). Sonuç: /opt/pentagi-run/api_token + graphql_path.
# NOT: İlk CANLI koşuda uçtan uca doğrulanacak; DO/secret basılmaz.
set -euo pipefail

# ————————————————————————————————————————————————————————————————————————————————————
# (D1 — BAĞIMSIZ ALTYAPI WATCHDOG) DROPLET-İÇİ SELF-DESTRUCT — orchestrator'ın Node sürecinden
# TAMAMEN AYRI. 3 kez aynı hata tekrarlandı: cap/süre kontrolü hep ORCHESTRATOR'ın kendi döngüsü
# içindeydi; o döngü tıkanınca (network gecikmesi, SSH asılması, docker run'ın sonsuz beklemesi)
# kontrol de onunla birlikte tıkandı — bir koşu 945s+/30dk+ asılı kaldı, kullanıcı elle kill-switch'e
# basmak zorunda kaldı. Bu EN BAŞTA (docker/PentAGI kurulmadan ÖNCE) kurulur ki setup/harden/verify/
# campaign HANGİ AŞAMADA asılırsa asılsın, droplet KENDİ KENDİNE (systemd, orchestrator'a muhtaç
# olmadan) belirlenen sürede kapanır. Bu, watchdog'ların watchdog'udur — son çare.
CAP_SEC="${1:-1200}"                 # orchestrator cfg.capSec geçirir; argüman yoksa güvenli varsayılan
# (ZAMANLAMA DÜZELTMESİ) Bu betik SETUP BAŞINDA çalışır; self-destruct saati BURADAN başlar. Setup ~8dk
# + kampanya (cap) + teardown sürer. cap+90 ÇOK ERKEN'di → droplet kampanya ~1dk'dayken kendini imha
# ediyordu (0 artefakt kök-nedenlerinden). Bu droplet-içi zamanlayıcı NİHAİ backstop'tur (her şey ölürse);
# Node-watchdog (kampanya başında, cap+60) asıl kesin kill'dir. Backstop'a bol setup+kampanya payı ver.
SELFDESTRUCT_SEC=$((CAP_SEC + 1200)) # cap + 20dk (setup ~8dk + kampanya + tampon) — erken imhayı önler
mkdir -p /opt/pentagi-run/audit
cat > /opt/pentagi-run/self-destruct.sh <<'SD'
#!/bin/bash
echo "$(date -u +%FT%TZ) SELF-DESTRUCT (droplet-içi bağımsız zamanlayıcı — orchestrator'dan TAMAMEN AYRI) tetiklendi" >> /opt/pentagi-run/audit/audit.log 2>/dev/null
docker ps -q 2>/dev/null | xargs -r docker kill 2>/dev/null
iptables -P OUTPUT DROP 2>/dev/null || true
iptables -F DOCKER-USER 2>/dev/null || true
iptables -A DOCKER-USER -j DROP 2>/dev/null || true
sync
shutdown -h now
SD
chmod +x /opt/pentagi-run/self-destruct.sh
systemctl reset-failed redteam-selfdestruct >/dev/null 2>&1 || true
systemd-run --unit=redteam-selfdestruct --on-active="${SELFDESTRUCT_SEC}s" /opt/pentagi-run/self-destruct.sh
echo "== D1: droplet-içi BAĞIMSIZ self-destruct kuruldu — cap=${CAP_SEC}s (+90s tampon) = ${SELFDESTRUCT_SEC}s sonra tetiklenecek =="
systemctl list-timers 'redteam-selfdestruct*' --all 2>/dev/null || true
# ————————————————————————————————————————————————————————————————————————————————————

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
# COOKIE_SIGNING_SALT: JWT imzalama anahtarının kaynağı — SERVER ve bootstrap AYNI değeri kullanmalı.
# Taze rastgele SET et (deterministik; .env.example default'u/boş bırakma). set +x zaten aktif → değer basılmaz.
_SALT="$(openssl rand -hex 16)"
if grep -q '^COOKIE_SIGNING_SALT=' .env; then
  sed -i "s|^COOKIE_SIGNING_SALT=.*|COOKIE_SIGNING_SALT=${_SALT}|" .env
else
  printf 'COOKIE_SIGNING_SALT=%s\n' "$_SALT" >> .env
fi
unset _SALT
sed -i "s|^DOCKER_NETWORK=.*|DOCKER_NETWORK=pentagi-network|" .env
sed -i "s|^ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=|" .env    # anahtar .env'e YAZILMAZ

# 4) Anahtar off-disk: compose override ile shell env'inden konteynere geç
cat > docker-compose.override.yml <<'YML'
services:
  pentagi:
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:?anahtar shell env ile verilmeli}
YML

# 4b) UCUZ KALİBRASYON (S1-test): PentAGI provider/model config'inde opus→sonnet indir.
# Gerekçe: image'da generator vb. roller Opus'a atanmış; kalibrasyon koşularında maliyeti ~%30 düşürür.
# Yalnız MODEL-TIER'ı düşürür — güvenlik/izolasyon/teardown/cap DEĞİŞMEZ. REDTEAM_NO_OPUS=0 ile kapatılır.
# Best-effort: config disk'ten okunuyorsa etkir; binary'e gömülüyse zararsız no-op (koşu model dağılımından teyit).
if [ "${REDTEAM_NO_OPUS:-1}" = "1" ]; then
  # (P0-4) opus geçen HER config dosyasını yakala: yml/yaml/json/.env + uzantısız .env türevleri.
  # 1) model-ID biçimindeki opus referansları → sonnet. 2) *_MODEL=... opus içeren env satırları → sonnet.
  # NOT: grep no-match'te 1, xargs 123 döndürür; set -euo pipefail altında bu script'i ÖLDÜRÜR
  # (kalibrasyon başarılı olup 0 opus kaldığında bile) → her iki pipeline da `|| true` ile korunur.
  find /opt/pentagi -maxdepth 5 -type f \( -name '*.yml' -o -name '*.yaml' -o -name '*.json' -o -name '*.env' -o -name '.env' -o -name '.env.*' -o -name 'env' \) 2>/dev/null \
    | { xargs -r grep -liE 'opus' 2>/dev/null || true; } \
    | while IFS= read -r f; do
        sed -i -E 's/claude-[a-z0-9._-]*opus[a-z0-9._-]*/claude-sonnet-4-5/g' "$f"
        sed -i -E 's/^([A-Z0-9_]*MODEL[A-Z0-9_]*=).*[Oo]pus.*/\1claude-sonnet-4-5/' "$f"
      done
  echo "[setup] ucuz kalibrasyon aktif: opus→sonnet (S1-test; güvenlik/izolasyon değişmez)"
  # (P0-4/P0-5 dürüstlük) Kalibrasyon SONRASI kalan opus referanslarını DÜRÜSTÇE say ve raporla — sıfır
  # değilse koşu opus sızdırabilir (config binary'e gömülü olabilir); sessizce "her şey sonnet" DEME.
  _opus_left="$(find /opt/pentagi -maxdepth 5 -type f 2>/dev/null | { xargs -r grep -liE 'opus' 2>/dev/null || true; } | wc -l | tr -d ' ')"
  echo "[setup] KALİBRASYON-TEYİT: kalan 'opus' geçen config dosyası = ${_opus_left} (0 hedeflenir; >0 ise koşu model dağılımından teyit edilmeli)"
fi

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
# Salt'ı SERVER'ın GERÇEK env'inden oku (çalışan pentagi container'ı → .env'den olası sapma YOK;
# JWT tam olarak server'ın kullandığı salt ile imzalanır → 403 uyuşmazlığı biter). Fallback: .env.
salt=subprocess.run(["docker","exec","pentagi","printenv","COOKIE_SIGNING_SALT"],capture_output=True,text=True).stdout.strip()
if not salt:
    for line in open("/opt/pentagi/.env"):
        if line.startswith("COOKIE_SIGNING_SALT="): salt=line.split("=",1)[1].strip()
assert salt, "COOKIE_SIGNING_SALT yok (container env + .env boş)"
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
# DOĞRULAMA: authed {__typename} DATA dönmeli (403 DEĞİL). Server tam hazır olması için retry (~80s).
# Token/salt ASLA basılmaz; yalnız yanıt-özeti (403 ise kısa hata, secret değil).
CTX=ssl.create_default_context(); CTX.check_hostname=False; CTX.verify_mode=ssl.CERT_NONE
ok=False; diag=""
for _ in range(20):
    try:
        req=urllib.request.Request("https://localhost:8443/api/v1/graphql",data=b'{"query":"{__typename}"}',
            headers={"Authorization":"Bearer "+tok,"content-type":"application/json"},method="POST")
        body=urllib.request.urlopen(req,context=CTX,timeout=15).read().decode()
        if '"data"' in body and '__typename' in body: ok=True; break
        diag=body[:80]
    except Exception as e:
        diag=str(e)[:80]
    time.sleep(4)
print("BOOTSTRAP AUTH:", "OK (token diske yazıldı, basılmadı)" if ok else ("FAIL: "+diag))
if not ok: raise SystemExit("bootstrap auth DOĞRULANAMADI (403? salt/token uyuşmazlığı) — setup DURDU")
PY
echo "setup-pentagi tamam."
