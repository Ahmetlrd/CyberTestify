-- (Mantık tutarlılığı) Test hesabıyla login GERÇEKTEN başarılı olduğu an damgalanır; LiveScanPhases
-- bu damga gelene kadar "Test hesabıyla oturum açılıyor" fazında sahte ilerlemez.
ALTER TABLE "Flow" ADD COLUMN IF NOT EXISTS "authConfirmedAt" TIMESTAMP(3);
