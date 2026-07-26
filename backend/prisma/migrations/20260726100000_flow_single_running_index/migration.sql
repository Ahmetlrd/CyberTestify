-- Concurrency=1 DB-level guvence: ayni anda YALNIZCA TEK 'running' Flow olabilir.
-- Kismi unique index (Prisma semasinda ifade edilemedigi icin elle yazildi).
-- Iki tarama tam ayni anda baslamaya calisirsa ikincinin insert'i P2002 ile
-- reddedilir → siparis kuyruga alinir (orchestrator.startScanForOrder).
CREATE UNIQUE INDEX "Flow_single_running_idx" ON "Flow" ("status") WHERE "status" = 'running';
