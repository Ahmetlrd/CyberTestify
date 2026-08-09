-- Aktif Doğrulama Paketi TEK-siparis modeli: enum degeri EKLE (additive). INSERT bir sonraki
-- migration'da (ADD VALUE ayni transaction'da KULLANILAMAZ).
ALTER TYPE "ScanPackageKey" ADD VALUE IF NOT EXISTS 'bundle_active_verify';
