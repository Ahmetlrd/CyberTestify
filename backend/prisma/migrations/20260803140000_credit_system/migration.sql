-- Is 2: Kredi/bundle sistemi — Customer.creditBalance + CreditTransaction ledger.
ALTER TABLE "Customer" ADD COLUMN IF NOT EXISTS "creditBalance" INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS "CreditTransaction" (
    "id" TEXT NOT NULL,
    "customerId" TEXT NOT NULL,
    "delta" INTEGER NOT NULL,
    "reason" TEXT NOT NULL,
    "bundleKey" TEXT,
    "orderId" TEXT,
    "balanceAfter" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "CreditTransaction_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "CreditTransaction_customerId_idx" ON "CreditTransaction"("customerId");

DO $$ BEGIN
  ALTER TABLE "CreditTransaction" ADD CONSTRAINT "CreditTransaction_customerId_fkey"
    FOREIGN KEY ("customerId") REFERENCES "Customer"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
