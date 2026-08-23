-- (S1 Otonom Red Team) RedTeamJob'u Order'a 1:1 bağla (ödemeli koşu). orderId nullable → eski
-- beta/operatör-tetikli koşular geriye uyumlu kalır. Enum değeri BURADA kullanılmaz (güvenli).
ALTER TABLE "RedTeamJob" ADD COLUMN "orderId" TEXT;
CREATE UNIQUE INDEX "RedTeamJob_orderId_key" ON "RedTeamJob"("orderId");
ALTER TABLE "RedTeamJob" ADD CONSTRAINT "RedTeamJob_orderId_fkey" FOREIGN KEY ("orderId") REFERENCES "Order"("id") ON DELETE SET NULL ON UPDATE CASCADE;
