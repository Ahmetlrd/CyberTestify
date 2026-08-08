-- Flow.idleSince: ajanin >0 arac cagrisi sonrasi kesintisiz 'waiting'e girdigi an.
-- Worker idle-waiting grace mekanizmasi bu alani kullanir (erken bitirmeyi onler).
ALTER TABLE "Flow" ADD COLUMN "idleSince" TIMESTAMP(3);
