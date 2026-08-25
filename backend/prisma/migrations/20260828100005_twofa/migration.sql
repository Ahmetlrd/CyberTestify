-- Customer 2FA (opt-in) + nudge
ALTER TABLE "Customer" ADD COLUMN "totpSecret" TEXT;
ALTER TABLE "Customer" ADD COLUMN "twofaEnabled" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "Customer" ADD COLUMN "twofaConfirmedAt" TIMESTAMP(3);
ALTER TABLE "Customer" ADD COLUMN "twofaRecoveryCodes" TEXT;
ALTER TABLE "Customer" ADD COLUMN "twofaFailedAttempts" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "Customer" ADD COLUMN "twofaLockedUntil" TIMESTAMP(3);
ALTER TABLE "Customer" ADD COLUMN "twofaNudgeDismissedAt" TIMESTAMP(3);
ALTER TABLE "Customer" ADD COLUMN "twofaNudgeRemindAfter" TIMESTAMP(3);

-- AdminUser 2FA (mandatory) — totpSecret zaten var
ALTER TABLE "AdminUser" ADD COLUMN "twofaEnabled" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "AdminUser" ADD COLUMN "twofaConfirmedAt" TIMESTAMP(3);
ALTER TABLE "AdminUser" ADD COLUMN "twofaRecoveryCodes" TEXT;
ALTER TABLE "AdminUser" ADD COLUMN "twofaFailedAttempts" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "AdminUser" ADD COLUMN "twofaLockedUntil" TIMESTAMP(3);
