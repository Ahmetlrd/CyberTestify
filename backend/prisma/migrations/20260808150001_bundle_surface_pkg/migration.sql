-- bundle_surface icin ScanPackage satiri (Order.packageId FK'si buna baglanir). deploy seed
-- calistirmadigi icin satir burada olusturulur (idempotent). promptTemplate placeholder — rapor
-- KOD tarafindan (generateBundleSurfaceReport) uretilir, ajan ciktisi kullanilmaz.
INSERT INTO "ScanPackage" ("id", "key", "displayName", "description", "priceMinorUnit", "modelProvider", "maxToolCalls", "promptTemplate", "active")
VALUES (
  gen_random_uuid(),
  'bundle_surface',
  'Dış Yüzey & Yapılandırma Paketi',
  'SSL/TLS, güvenlik başlıkları, DNS/e-posta, CORS ve CSP yapılandırmasını tek raporda inceleyen kombine paket.',
  399900,
  'cybertestify-anthropic',
  30,
  'PASSIVE data-collection only for the External Surface bundle (SSL/TLS, HTTP security headers, DNS/email, CORS, CSP). The final report is generated deterministically by code; no free-form report writing is needed. Target: {{TARGET_HOST}}',
  true
)
ON CONFLICT ("key") DO NOTHING;
