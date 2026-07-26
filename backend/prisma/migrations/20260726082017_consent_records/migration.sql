-- AlterTable
ALTER TABLE "Customer" ADD COLUMN     "termsAcceptedAt" TIMESTAMP(3),
ADD COLUMN     "termsVersion" TEXT;

-- AlterTable
ALTER TABLE "Order" ADD COLUMN     "consentIp" TEXT,
ADD COLUMN     "consentVersion" TEXT,
ADD COLUMN     "distanceContractAcceptedAt" TIMESTAMP(3),
ADD COLUMN     "withdrawalWaivedAt" TIMESTAMP(3);
