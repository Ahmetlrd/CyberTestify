-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "ScanPackageKey" ADD VALUE 'ssl_tls';
ALTER TYPE "ScanPackageKey" ADD VALUE 'header_leak';
ALTER TYPE "ScanPackageKey" ADD VALUE 'dns_email';
ALTER TYPE "ScanPackageKey" ADD VALUE 'cms_cve';
ALTER TYPE "ScanPackageKey" ADD VALUE 'kvkk_hazirlik';
ALTER TYPE "ScanPackageKey" ADD VALUE 'iso27001_hazirlik';

-- AlterTable
ALTER TABLE "Order" ADD COLUMN     "ownershipConfirmedAt" TIMESTAMP(3);
