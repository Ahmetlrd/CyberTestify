-- Ic yonetim paneli (admin) — MUSTERI sisteminden ayri kullanici tablosu.
CREATE TABLE "AdminUser" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "totpSecret" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastLoginAt" TIMESTAMP(3),
    CONSTRAINT "AdminUser_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "AdminUser_email_key" ON "AdminUser"("email");
