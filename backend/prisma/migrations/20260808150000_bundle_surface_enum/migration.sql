-- Bundle TEK-siparis modeli: bundle bir ScanPackage gibi davranir. Enum degeri EKLE (additive).
-- (ADD VALUE ayni transaction'da KULLANILAMAZ; INSERT bir sonraki migration'da.)
ALTER TYPE "ScanPackageKey" ADD VALUE IF NOT EXISTS 'bundle_surface';
