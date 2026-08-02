-- (2) Cok-dilli cikti: siparise locale.
ALTER TABLE "Order" ADD COLUMN "locale" TEXT NOT NULL DEFAULT 'tr';

-- (3) Ucretli eklenti "AI Cozum Onerileri": ana rapordan ayri, sifreli, kilitli.
ALTER TABLE "Report" ADD COLUMN "fixSuggestions" BYTEA;
ALTER TABLE "Report" ADD COLUMN "fixSuggestionsIv" BYTEA;
ALTER TABLE "Report" ADD COLUMN "fixSuggestionsAuthTag" BYTEA;
ALTER TABLE "Report" ADD COLUMN "fixSuggestionsSalt" BYTEA;
ALTER TABLE "Report" ADD COLUMN "fixSuggestionsUnlockedAt" TIMESTAMP(3);
