-- Sifre sifirlama alanlari (token SHA-256 hash'i + son gecerlilik)
ALTER TABLE "Customer" ADD COLUMN "resetTokenHash" TEXT;
ALTER TABLE "Customer" ADD COLUMN "resetTokenExpiry" TIMESTAMP(3);
