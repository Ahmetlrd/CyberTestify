-- Faz 3 genisletme: yeni active-light/active-verify-only paket enum degerleri (available:false).
ALTER TYPE "ScanPackageKey" ADD VALUE IF NOT EXISTS 'ssrf_verify';
ALTER TYPE "ScanPackageKey" ADD VALUE IF NOT EXISTS 'file_upload_verify';
ALTER TYPE "ScanPackageKey" ADD VALUE IF NOT EXISTS 'business_logic_verify';
ALTER TYPE "ScanPackageKey" ADD VALUE IF NOT EXISTS 'race_massassign_verify';
ALTER TYPE "ScanPackageKey" ADD VALUE IF NOT EXISTS 'rce_verify';
ALTER TYPE "ScanPackageKey" ADD VALUE IF NOT EXISTS 'authenticated_scan';
ALTER TYPE "ScanPackageKey" ADD VALUE IF NOT EXISTS 'autonomous_pentest';
