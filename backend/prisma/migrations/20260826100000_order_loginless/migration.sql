-- (LOGİNSİZ TEST) Kimlik-doğrulamalı paketin login olmadan koşabilmesi için bayrak.
ALTER TABLE "Order" ADD COLUMN IF NOT EXISTS "loginless" BOOLEAN NOT NULL DEFAULT false;
