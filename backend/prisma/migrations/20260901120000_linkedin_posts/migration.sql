-- (LINKEDIN OTOMATIK PAYLASIM) Admin panelinden olusturulan LinkedIn gonderileri.
CREATE TABLE "LinkedinPost" (
    "id" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "mediaUrl" TEXT,
    "status" TEXT NOT NULL DEFAULT 'DRAFT',
    "scheduledFor" TIMESTAMP(3),
    "bufferPostId" TEXT,
    "errorMessage" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "LinkedinPost_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "LinkedinPost_status_createdAt_idx" ON "LinkedinPost"("status", "createdAt");
