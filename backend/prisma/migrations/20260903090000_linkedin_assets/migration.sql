-- (LINKEDIN MEDYA) PDF carousel / gorsel dosyalari
CREATE TABLE "LinkedinAsset" (
    "id" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "mime" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "data" BYTEA NOT NULL,
    "bytes" INTEGER NOT NULL,
    "pages" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "LinkedinAsset_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "LinkedinAsset_kind_createdAt_idx" ON "LinkedinAsset"("kind", "createdAt");
