-- (Gözlemlenebilirlik) Taramanın adım-adım yapılandırılmış logu. Best-effort yazılır;
-- Order silinirse cascade ile temizlenir. Retention: worker periyodik siler.
CREATE TABLE "ScanLog" (
    "id" TEXT NOT NULL,
    "orderId" TEXT NOT NULL,
    "seq" INTEGER NOT NULL,
    "ts" TIMESTAMP(3) NOT NULL,
    "step" TEXT NOT NULL,
    "level" TEXT NOT NULL DEFAULT 'info',
    "method" TEXT,
    "url" TEXT,
    "status" INTEGER,
    "durationMs" INTEGER,
    "sizeBytes" INTEGER,
    "rule" TEXT,
    "severity" TEXT,
    "summary" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ScanLog_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "ScanLog_orderId_seq_idx" ON "ScanLog"("orderId", "seq");
CREATE INDEX "ScanLog_createdAt_idx" ON "ScanLog"("createdAt");

ALTER TABLE "ScanLog" ADD CONSTRAINT "ScanLog_orderId_fkey" FOREIGN KEY ("orderId") REFERENCES "Order"("id") ON DELETE CASCADE ON UPDATE CASCADE;
