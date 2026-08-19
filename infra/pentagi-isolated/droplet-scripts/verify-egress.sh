#!/usr/bin/env bash
# (3b-ii) Kampanya ÖNCESİ AMPİRİK izolasyon doğrulaması — pentagi-network üstünde throwaway
# konteynerden: yetkili HEDEF erişilir mi + CyberTestify prod BLOCKED mı. Orchestrator çıktıda
# "TARGET_OK" ve "CYBERTESTIFY_BLOCKED" ikisini de görmezse kampanyayı İPTAL eder.
set -euo pipefail
TARGET_IP="${1:?kullanım: verify-egress.sh <yetkili-hedef-ip>}"
CT_PUBLIC="164.92.223.208"
IMG="vxcontrol/kali-linux"

probe() { docker run --rm --network pentagi-network "$IMG" sh -lc "$1" 2>/dev/null; }

T=$(probe "curl -s -o /dev/null -w '%{http_code}' --max-time 8 http://$TARGET_IP/ || curl -s -o /dev/null -w '%{http_code}' --max-time 8 https://$TARGET_IP/ || echo 000")
C=$(probe "curl -s -o /dev/null -w '%{http_code}' --max-time 8 https://$CT_PUBLIC/ || echo 000")
M=$(probe "curl -s -o /dev/null -w '%{http_code}' --max-time 6 http://169.254.169.254/ || echo 000")

echo "target($TARGET_IP)=$T  cybertestify=$C  metadata=$M"
[ -n "$T" ] && [ "$T" != "000" ] && echo "TARGET_OK" || { echo "TARGET_FAIL"; }
[ "$C" = "000" ] && echo "CYBERTESTIFY_BLOCKED" || echo "CYBERTESTIFY_LEAK"
[ "$M" = "000" ] && echo "METADATA_BLOCKED" || echo "METADATA_LEAK"
