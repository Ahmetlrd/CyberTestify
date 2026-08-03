-- Faz 3: Active-light paketler icin zorunlu yetkilendirme/onay beyani.
CREATE TABLE IF NOT EXISTS "ActiveTestConsent" (
    "id" TEXT NOT NULL,
    "customerId" TEXT NOT NULL,
    "orderId" TEXT NOT NULL,
    "packageKey" "ScanPackageKey" NOT NULL,
    "legalName" TEXT NOT NULL,
    "companyName" TEXT,
    "riskAccepted" BOOLEAN NOT NULL,
    "textVersion" TEXT NOT NULL,
    "consentIp" TEXT,
    "pdfDelivered" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ActiveTestConsent_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "ActiveTestConsent_orderId_key" ON "ActiveTestConsent"("orderId");
CREATE INDEX IF NOT EXISTS "ActiveTestConsent_customerId_idx" ON "ActiveTestConsent"("customerId");

DO $$ BEGIN
  ALTER TABLE "ActiveTestConsent" ADD CONSTRAINT "ActiveTestConsent_customerId_fkey"
    FOREIGN KEY ("customerId") REFERENCES "Customer"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "ActiveTestConsent" ADD CONSTRAINT "ActiveTestConsent_orderId_fkey"
    FOREIGN KEY ("orderId") REFERENCES "Order"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
