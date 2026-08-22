#!/usr/bin/env bash
# (3b-ii) Kampanya ÖNCESİ AMPİRİK izolasyon gate — pentagi-network throwaway konteynerden.
# İki koşul AYRI raporlanır: yetkili HEDEF erişilir mi + CyberTestify/metadata BLOCKED mı.
# reachability = TCP + (TLS/HTTP) HERHANGİ yanıt (HTTP kodu önemli DEĞİL; amaç egress hedefe İZİN
# veriyor mu). -k: sertifika IP ile SNI uyuşmayabilir → doğrulamayı atla (yoksa yanlış 'erişilemez').
set -uo pipefail
TARGET_IP="${1:?kullanım: verify-egress.sh <yetkili-hedef-ip>}"
CT_PUBLIC="164.92.223.208"
IMG="vxcontrol/kali-linux"

# curl EXIT 0 = bağlantı kuruldu + yanıt geldi (kod ne olursa olsun) → ulaşılabilir.
# (KÖK-NEDEN DÜZELTME) `timeout 40 docker run` — bloklanan hedeflere (CyberTestify/metadata) yapılan
# docker-run'ın asılıp SSH oturumunu düşürmesini (→ exit 255) engeller. `|| true` ile docker/timeout'un
# sıfır-olmayan dönüşü betiği ETKİLEMEZ — sonucu yalnız curl'ün erişilebilirliği belirler.
can_reach() {
  timeout 40 docker run --rm --network pentagi-network "$IMG" sh -lc "
    curl -sS -o /dev/null --connect-timeout 6 --max-time 10 -k https://$1/ 2>/dev/null \
    || curl -sS -o /dev/null --connect-timeout 6 --max-time 10 http://$1/ 2>/dev/null" >/dev/null 2>&1
}

TARGET_OK=0; CT_BLOCKED=0
if can_reach "$TARGET_IP"; then echo "target-reachable: yes"; echo "TARGET_OK"; TARGET_OK=1; else echo "target-reachable: no"; echo "TARGET_FAIL"; fi
if can_reach "$CT_PUBLIC"; then echo "cybertestify-blocked: no";  echo "CYBERTESTIFY_OPEN"; else echo "cybertestify-blocked: yes"; echo "CYBERTESTIFY_BLOCKED"; CT_BLOCKED=1; fi
# metadata YALNIZ bilgi amaçlı (fatal değil); asılırsa/hata verirse betiği düşürmesin.
if can_reach "169.254.169.254"; then echo "metadata-blocked: no"; echo "METADATA_OPEN"; else echo "metadata-blocked: yes"; echo "METADATA_BLOCKED"; fi

# ÇIKIŞ KODU = GEREKLİ iki koşulun sonucu (son komutun rastlantısal koduna DEĞİL): hedef erişilir +
# CyberTestify BLOCKED. Böylece betiğin exit'i gerçekte yaptığı kontrolü DOĞRU yansıtır (deterministik).
if [ "$TARGET_OK" = 1 ] && [ "$CT_BLOCKED" = 1 ]; then exit 0; else exit 2; fi
