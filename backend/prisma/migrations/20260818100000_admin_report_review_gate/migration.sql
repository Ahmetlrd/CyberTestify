-- (İç kalite kapısı) Tarama sonrası admin onayı: yeni OrderStatus değeri + Report.adminReleasedAt.
-- PG 12+ ADD VALUE bir transaction içinde çalışabilir (değer aynı tx'te KULLANILMADIĞI sürece).
ALTER TYPE "OrderStatus" ADD VALUE IF NOT EXISTS 'awaiting_admin_review';

ALTER TABLE "Report" ADD COLUMN IF NOT EXISTS "adminReleasedAt" TIMESTAMP(3);
