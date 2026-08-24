-- (COK-BOLGE) Order'a "hangi bolgeden geldi" ETIKETI. locale=DIL iken region=BOLGE (us/ae ikisi de
-- en-locale ama ayri bolge). Uygulama/admin akisi bolge-BAGIMSIZ kalir; bu alan yalniz gorunurluk/
-- ilerideki bolge-bazli raporlama icindir. Eski siparisler icin varsayilan 'tr'.
ALTER TABLE "Order" ADD COLUMN "region" TEXT NOT NULL DEFAULT 'tr';
