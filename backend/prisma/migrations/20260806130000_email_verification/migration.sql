-- E-posta dogrulama alanlari
ALTER TABLE "Customer" ADD COLUMN "emailVerified" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "Customer" ADD COLUMN "emailVerifyCodeHash" TEXT;
ALTER TABLE "Customer" ADD COLUMN "emailVerifyCodeExpiry" TIMESTAMP(3);

-- MEVCUT (bu ozellikten ONCE kayitli) TUM hesaplari verified say — mağdur etme.
-- Yalniz bundan SONRA kayit olacak yeni hesaplar dogrulama akisindan gecer.
UPDATE "Customer" SET "emailVerified" = true;
