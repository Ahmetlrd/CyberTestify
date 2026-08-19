-- (Otonom AI Red Team — 3b-ii) Gated tetikten oluşan iş kaydı. Order/Report akışından AYRI.
CREATE TABLE "RedTeamJob" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "customerId" TEXT,
    "idempotencyKey" TEXT NOT NULL,
    "domain" TEXT NOT NULL,
    "level" TEXT NOT NULL,
    "environment" TEXT NOT NULL,
    "ownershipConfirmed" BOOLEAN NOT NULL DEFAULT false,
    "riskAccepted" BOOLEAN NOT NULL DEFAULT false,
    "prodElevatedAccepted" BOOLEAN NOT NULL DEFAULT false,
    "consentIp" TEXT,
    "status" TEXT NOT NULL DEFAULT 'queued',
    "startedAt" TIMESTAMP(3),
    "finishedAt" TIMESTAMP(3),
    "dropletId" TEXT,
    "targetIp" TEXT,
    "llmCalls" INTEGER,
    "costUsd" DOUBLE PRECISION,
    "reportJson" JSONB,
    "log" JSONB,
    "error" TEXT,
    CONSTRAINT "RedTeamJob_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "RedTeamJob_idempotencyKey_key" ON "RedTeamJob"("idempotencyKey");
CREATE INDEX "RedTeamJob_status_idx" ON "RedTeamJob"("status");
CREATE INDEX "RedTeamJob_createdAt_idx" ON "RedTeamJob"("createdAt");

ALTER TABLE "RedTeamJob" ADD CONSTRAINT "RedTeamJob_customerId_fkey" FOREIGN KEY ("customerId") REFERENCES "Customer"("id") ON DELETE SET NULL ON UPDATE CASCADE;
