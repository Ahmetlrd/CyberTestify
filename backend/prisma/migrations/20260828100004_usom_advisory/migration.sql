-- CreateTable
CREATE TABLE "UsomAdvisory" (
    "id" SERIAL NOT NULL,
    "trNo" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "publishedAt" TIMESTAMP(3),
    "matchKind" TEXT NOT NULL,
    "matchKey" TEXT,
    "cve" TEXT,
    "versionLt" TEXT,
    "syncedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UsomAdvisory_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "UsomAdvisory_trNo_key" ON "UsomAdvisory"("trNo");

-- CreateIndex
CREATE INDEX "UsomAdvisory_matchKind_idx" ON "UsomAdvisory"("matchKind");
