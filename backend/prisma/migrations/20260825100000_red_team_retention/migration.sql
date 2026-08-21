-- Red Team şeffaflık + retention: teardown sonrası transkript/karar-izi/re-bind için ham veri saklama.
ALTER TABLE "RedTeamJob" ADD COLUMN IF NOT EXISTS "rawFlowJson" JSONB;
ALTER TABLE "RedTeamJob" ADD COLUMN IF NOT EXISTS "binderTraceJson" JSONB;
ALTER TABLE "RedTeamJob" ADD COLUMN IF NOT EXISTS "transcriptJson" JSONB;
