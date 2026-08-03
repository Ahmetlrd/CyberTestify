-- Faz 3: ilk active-light paket enum degerleri (available:false — fiyat/onay bekliyor).
ALTER TYPE "ScanPackageKey" ADD VALUE IF NOT EXISTS 'injection_verify';
ALTER TYPE "ScanPackageKey" ADD VALUE IF NOT EXISTS 'idor_verify';
