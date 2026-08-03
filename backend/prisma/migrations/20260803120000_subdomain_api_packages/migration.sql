-- FAZ 2: iki yeni pasif paket enum degeri (available:false — placeholder fiyat).
ALTER TYPE "ScanPackageKey" ADD VALUE IF NOT EXISTS 'subdomain_takeover';
ALTER TYPE "ScanPackageKey" ADD VALUE IF NOT EXISTS 'api_discovery';
