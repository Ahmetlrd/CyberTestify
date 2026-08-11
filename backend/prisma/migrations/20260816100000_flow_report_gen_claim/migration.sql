-- (Fix) Deterministik/authenticated rapor uretimi CLAIM damgasi — worker restart'ta tek-kullanimlik
-- test kimlik bilgisinin ikinci kez tuketilmesini (no_login_endpoint) onler.
ALTER TABLE "Flow" ADD COLUMN "reportGenStartedAt" TIMESTAMP(3);
