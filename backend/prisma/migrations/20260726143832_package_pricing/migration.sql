-- CreateTable
CREATE TABLE "PackagePricing" (
    "id" TEXT NOT NULL,
    "packageKey" "ScanPackageKey" NOT NULL,
    "region" TEXT NOT NULL,
    "currency" TEXT NOT NULL,
    "amountMinorUnit" INTEGER NOT NULL,

    CONSTRAINT "PackagePricing_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "PackagePricing_packageKey_region_key" ON "PackagePricing"("packageKey", "region");

-- AddForeignKey
ALTER TABLE "PackagePricing" ADD CONSTRAINT "PackagePricing_packageKey_fkey" FOREIGN KEY ("packageKey") REFERENCES "ScanPackage"("key") ON DELETE RESTRICT ON UPDATE CASCADE;
