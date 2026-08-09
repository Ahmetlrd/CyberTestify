-- (Aktif Doğrulama Paketi) Ödeme öncesi "düşük kapsam" uyarısı: gösterildi mi + onay zaman damgası.
ALTER TABLE "Order" ADD COLUMN IF NOT EXISTS "lowScopeWarningShown" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "Order" ADD COLUMN IF NOT EXISTS "lowScopeWarningAcknowledgedAt" TIMESTAMP(3);
