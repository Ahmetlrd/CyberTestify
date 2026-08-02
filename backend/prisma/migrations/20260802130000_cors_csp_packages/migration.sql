-- Iki yeni pasif paket: CORS & Cerez Guvenligi, CSP Analizi.
ALTER TYPE "ScanPackageKey" ADD VALUE IF NOT EXISTS 'cors_cookie';
ALTER TYPE "ScanPackageKey" ADD VALUE IF NOT EXISTS 'csp_analiz';
