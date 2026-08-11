-- Tarama deneme sayaci + musteri iade talebi (retry / refund-request akisi)
ALTER TABLE "Order" ADD COLUMN "attemptCount" INTEGER NOT NULL DEFAULT 1;
ALTER TABLE "Order" ADD COLUMN "refundRequestedAt" TIMESTAMP(3);
ALTER TABLE "Order" ADD COLUMN "refundRequestReason" TEXT;
