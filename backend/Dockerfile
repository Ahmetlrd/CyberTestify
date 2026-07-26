# CyberTestify backend — api / worker / egress-proxy icin ortak imaj.
# Ayni imaj, docker-compose'da farkli komutlarla 3 servis olarak calisir.
FROM node:20-alpine AS base
WORKDIR /app
RUN apk add --no-cache wget
COPY package.json package-lock.json* ./
RUN npm ci || npm install
COPY prisma ./prisma
RUN npx prisma generate
COPY tsconfig.json ./
COPY src ./src
# tsx ile calistiriyoruz (build adimina gerek yok); prod'da `npm run build` +
# `node dist/...` tercih edilebilir.
EXPOSE 4000 8899
CMD ["npx", "tsx", "src/server.ts"]
