-- Ücretsiz (anlık ön-tarama) logu — ana sayfada girilen her alan adı + sonucu
CREATE TABLE "InstantScanLog" (
  "id" TEXT NOT NULL,
  "host" TEXT NOT NULL,
  "status" TEXT NOT NULL,
  "score" INTEGER,
  "grade" TEXT,
  "findings" INTEGER,
  "httpStatus" INTEGER,
  "region" TEXT NOT NULL DEFAULT 'tr',
  "ip" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "InstantScanLog_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "InstantScanLog_createdAt_idx" ON "InstantScanLog"("createdAt");
