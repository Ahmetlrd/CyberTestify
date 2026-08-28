-- PromoCode paket kısıtı: null = tüm paketler; set = yalnız o packageKey (ör. basit_tarama)
ALTER TABLE "PromoCode" ADD COLUMN "packageKey" TEXT;
