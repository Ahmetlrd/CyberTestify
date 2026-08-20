# CyberTestify backend — api / worker / egress-proxy icin ortak imaj.
# Ayni imaj, docker-compose'da farkli komutlarla 3 servis olarak calisir.
FROM node:20-alpine AS base
WORKDIR /app
# openssl: Prisma'nin (Alpine/musl) schema & query engine'i libssl'e ihtiyac duyar;
# olmadan "failed to detect libssl" -> migrate/seed patlar.
# chromium + fontlar: (3) rapor PDF uretimi icin (puppeteer-core headless Chromium).
# nss/freetype/harfbuzz/ttf-* Chromium'un render bagimliliklari; font-noto-* Turkce +
# genis Unicode (ekran goruntusu/rapor icerigi) icin. Puppeteer kendi Chromium'unu
# INDIRMEZ (sistemdekini kullaniriz) — PUPPETEER_SKIP_DOWNLOAD + EXECUTABLE_PATH.
RUN apk add --no-cache wget openssl \
      chromium nss freetype harfbuzz ca-certificates ttf-freefont font-noto \
      openssh-client curl jq
# (Otonom Red Team runner) openssh-client=ssh/ssh-keygen/scp (droplet kontrol-kanalı), curl+jq
# = DO API provision/teardown. python3 GEREKMEZ (launch_cap.py/binder.py DROPLET'te çalışır).
ENV PUPPETEER_SKIP_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser
COPY package.json package-lock.json* ./
RUN npm ci || npm install
COPY prisma ./prisma
RUN npx prisma generate
# Alpine/musl'da Prisma runtime openssl surumunu bazen tespit edemeyip yanlis
# engine adini (libquery_engine-linux-musl.so.node / openssl-1.1) arayip patliyor.
# binaryTargets ile URETILEN openssl-3.0.x engine'ini ACIKCA zorla (deterministik).
ENV PRISMA_QUERY_ENGINE_LIBRARY=/app/node_modules/.prisma/client/libquery_engine-linux-musl-openssl-3.0.x.so.node
COPY tsconfig.json ./
COPY src ./src
# tsx ile calistiriyoruz (build adimina gerek yok); prod'da `npm run build` +
# `node dist/...` tercih edilebilir.
EXPOSE 4000 8899
CMD ["npx", "tsx", "src/server.ts"]
