-- (İŞ 2) Kredi sistemini tamamen kaldır
DROP TABLE IF EXISTS "CreditTransaction";
ALTER TABLE "Customer" DROP COLUMN IF EXISTS "creditBalance";

-- (İŞ 2) Order: tarama başarısızlık sebebi (admin görünürlüğü — login-başarısız vb.)
ALTER TABLE "Order" ADD COLUMN "failureReason" TEXT;

-- (Fatura talebi — MANUEL) enum + tablo
DO $$ BEGIN
  CREATE TYPE "InvoiceType" AS ENUM ('bireysel', 'kurumsal');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
  CREATE TYPE "InvoiceStatus" AS ENUM ('requested', 'issued', 'sent');
EXCEPTION WHEN duplicate_object THEN null; END $$;

CREATE TABLE "InvoiceRequest" (
  "id"           TEXT NOT NULL,
  "orderId"      TEXT NOT NULL,
  "type"         "InvoiceType" NOT NULL,
  "companyName"  TEXT,
  "taxOffice"    TEXT,
  "taxNumber"    TEXT,
  "fullName"     TEXT,
  "nationalId"   TEXT,
  "address"      TEXT NOT NULL,
  "invoiceEmail" TEXT NOT NULL,
  "status"       "InvoiceStatus" NOT NULL DEFAULT 'requested',
  "notes"        TEXT,
  "requestedAt"  TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "issuedAt"     TIMESTAMP(3),
  "sentAt"       TIMESTAMP(3),
  "updatedAt"    TIMESTAMP(3) NOT NULL,
  CONSTRAINT "InvoiceRequest_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "InvoiceRequest_orderId_key" ON "InvoiceRequest"("orderId");
CREATE INDEX "InvoiceRequest_status_idx" ON "InvoiceRequest"("status");

ALTER TABLE "InvoiceRequest" ADD CONSTRAINT "InvoiceRequest_orderId_fkey"
  FOREIGN KEY ("orderId") REFERENCES "Order"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
