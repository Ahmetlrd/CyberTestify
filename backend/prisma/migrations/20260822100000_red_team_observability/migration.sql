-- (3b-ii gözlemlenebilirlik) RedTeamJob canlı-gözlem alanları + pull edilen log tablosu.
ALTER TABLE "RedTeamJob" ADD COLUMN "dropletIp" TEXT;
ALTER TABLE "RedTeamJob" ADD COLUMN "phase" TEXT;
ALTER TABLE "RedTeamJob" ADD COLUMN "elapsedSec" INTEGER;
ALTER TABLE "RedTeamJob" ADD COLUMN "egressTargetOk" BOOLEAN;
ALTER TABLE "RedTeamJob" ADD COLUMN "egressCyberBlocked" BOOLEAN;
ALTER TABLE "RedTeamJob" ADD COLUMN "lastPulledAt" TIMESTAMP(3);

CREATE TABLE "RedTeamJobLog" (
    "id" TEXT NOT NULL,
    "jobId" TEXT NOT NULL,
    "seq" INTEGER NOT NULL,
    "at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "source" TEXT NOT NULL,
    "phase" TEXT,
    "level" TEXT NOT NULL DEFAULT 'info',
    "message" TEXT NOT NULL,
    CONSTRAINT "RedTeamJobLog_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "RedTeamJobLog_jobId_seq_key" ON "RedTeamJobLog"("jobId", "seq");
CREATE INDEX "RedTeamJobLog_jobId_seq_idx" ON "RedTeamJobLog"("jobId", "seq");

ALTER TABLE "RedTeamJobLog" ADD CONSTRAINT "RedTeamJobLog_jobId_fkey" FOREIGN KEY ("jobId") REFERENCES "RedTeamJob"("id") ON DELETE CASCADE ON UPDATE CASCADE;
