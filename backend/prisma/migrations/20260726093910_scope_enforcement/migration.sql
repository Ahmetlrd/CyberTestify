-- AlterEnum
ALTER TYPE "OrderStatus" ADD VALUE 'scope_violation';

-- AlterTable
ALTER TABLE "Domain" ADD COLUMN     "hostingType" TEXT NOT NULL DEFAULT 'unknown',
ADD COLUMN     "resolvedIps" TEXT;

-- AlterTable
ALTER TABLE "Flow" ADD COLUMN     "scopeViolationTarget" TEXT;
