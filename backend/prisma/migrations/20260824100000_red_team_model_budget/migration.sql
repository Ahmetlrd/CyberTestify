-- (Otonom Red Team — model yönetimi + bütçe) RedTeamJob'a model config + cap override + tahmin + kullanım.
ALTER TABLE "RedTeamJob" ADD COLUMN "modelConfig" JSONB;
ALTER TABLE "RedTeamJob" ADD COLUMN "capCallsOverride" INTEGER;
ALTER TABLE "RedTeamJob" ADD COLUMN "capSecOverride" INTEGER;
ALTER TABLE "RedTeamJob" ADD COLUMN "capCostOverride" DOUBLE PRECISION;
ALTER TABLE "RedTeamJob" ADD COLUMN "estCostUsd" DOUBLE PRECISION;
ALTER TABLE "RedTeamJob" ADD COLUMN "modelUsage" JSONB;
