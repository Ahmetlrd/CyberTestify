# CyberTestify — PentAGI terminal (komut calistirma) container'i icin PASIF-RECON
# arac seti gomulu hafif image.
#
# NEDEN: PentAGI varsayilan terminal image'i `debian:latest` CIPLAK gelir — icinde
# curl/wget/openssl/dig/nslookup/host/python3 YOKTUR. Bu yuzden ssl_tls (openssl
# s_client) ve dns_email (dig) gibi CLI-araci gerektiren pasif paketlerde ajan ya
# butun tool-call butcesini "araci kurmaya" harciyor (eski davranis) ya da — bizim
# NO-INSTALL kuralimizdan sonra — hicbir araci bulamayip bos rapor uretiyordu.
#
# COZUM: bu araclari BASTAN gomeriz; ajan kurulum yapmadan dogrudan kullanir,
# butce israfi olmaz, NO-INSTALL kurali da artik dogru (araclar zaten var).
#
# SADECE PASIF/gozlem araclari — saldiri/exploit araci (nmap/sqlmap/metasploit vb.)
# BILINCLI olarak YOK; saldirgan is icin PentAGI'nin ayri kali image'i kullanilir
# (DOCKER_DEFAULT_IMAGE_FOR_PENTEST), biz onu kullanmiyoruz.
FROM debian:trixie-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      wget \
      openssl \
      dnsutils \
      bind9-host \
      python3 \
      jq \
 && rm -rf /var/lib/apt/lists/*

# Ajan komutlari /work altinda calisir (PentAGI DOCKER_WORK_DIR).
WORKDIR /work
CMD ["sleep", "infinity"]
