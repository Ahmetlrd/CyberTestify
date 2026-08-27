-- Blog gorsel kutuphanesi (kategori etiketli) + makale kapak/kategori alanlari
CREATE TABLE "BlogImage" (
  "id" TEXT NOT NULL,
  "category" TEXT NOT NULL,
  "mime" TEXT NOT NULL DEFAULT 'image/webp',
  "data" BYTEA NOT NULL,
  "width" INTEGER,
  "height" INTEGER,
  "alt" TEXT,
  "usedCount" INTEGER NOT NULL DEFAULT 0,
  "lastUsedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "BlogImage_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "BlogImage_category_lastUsedAt_idx" ON "BlogImage"("category", "lastUsedAt");

ALTER TABLE "BlogPost" ADD COLUMN "category" TEXT;
ALTER TABLE "BlogPost" ADD COLUMN "coverImageId" TEXT;
ALTER TABLE "BlogPost" ADD COLUMN "coverManual" BOOLEAN NOT NULL DEFAULT false;
