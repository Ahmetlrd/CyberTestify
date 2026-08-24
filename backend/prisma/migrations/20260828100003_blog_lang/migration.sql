-- (Cok-dilli blog) BlogPost'a dil/bolge alani. Mevcut TUM yazilar 'tr' (varsayilan) — /tr/blog'da kalir.
-- slug tekilligi artik dil bazli: ayni slug tr + de'de ayri yazi olabilir (ceviri).
ALTER TABLE "BlogPost" ADD COLUMN "lang" TEXT NOT NULL DEFAULT 'tr';

-- Eski tekil slug kisitini kaldir, [slug, lang] bileske tekile gec.
DROP INDEX IF EXISTS "BlogPost_slug_key";
CREATE UNIQUE INDEX "BlogPost_slug_lang_key" ON "BlogPost"("slug", "lang");
CREATE INDEX "BlogPost_status_lang_publishedAt_idx" ON "BlogPost"("status", "lang", "publishedAt");
