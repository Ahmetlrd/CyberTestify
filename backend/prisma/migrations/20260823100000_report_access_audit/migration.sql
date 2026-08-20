-- (Admin okuma — hesap verebilirlik) Değiştirilemez audit: admin rapor-erişimleri. FK YOK (rapor
-- silinse bile kayıt kalır). Secret ASLA yazılmaz.
CREATE TABLE "ReportAccessLog" (
    "id" TEXT NOT NULL,
    "at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "adminId" TEXT NOT NULL,
    "reportId" TEXT NOT NULL,
    "orderId" TEXT NOT NULL,
    "customerId" TEXT NOT NULL,
    "customerEmail" TEXT NOT NULL,
    "action" TEXT NOT NULL DEFAULT 'view_pdf',
    "ip" TEXT,
    CONSTRAINT "ReportAccessLog_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "ReportAccessLog_reportId_idx" ON "ReportAccessLog"("reportId");
CREATE INDEX "ReportAccessLog_adminId_idx" ON "ReportAccessLog"("adminId");
CREATE INDEX "ReportAccessLog_at_idx" ON "ReportAccessLog"("at");
