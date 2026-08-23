-- (S1 Otonom Red Team) ScanPackageKey enum'una redteam_s1 EKLE (additive). Değeri KULLANAN INSERT/
-- kolon bir sonraki migration'da (ADD VALUE aynı transaction'da kullanılamaz — Postgres kısıtı).
ALTER TYPE "ScanPackageKey" ADD VALUE IF NOT EXISTS 'redteam_s1';
