/**
 * (ADMIN OKUMA — HESAP VEREBİLİRLİK) Admin rapor-erişimi audit kaydı. Değiştirilemez (append-only;
 * mutasyon YOK). SECRET/ANAHTAR/rapor-içeriği ASLA yazılmaz — yalnız kim/ne zaman/hangi rapor/müşteri.
 */
import { prisma } from '../db.js';

export type ReportAccessAction = 'view_pdf' | 'approve_release';

export async function logReportAccess(input: {
  adminId: string;
  reportId: string;
  orderId: string;
  customerId: string;
  customerEmail: string;
  action: ReportAccessAction;
  ip?: string | null;
}): Promise<void> {
  try {
    await prisma.reportAccessLog.create({
      data: {
        adminId: input.adminId,
        reportId: input.reportId,
        orderId: input.orderId,
        customerId: input.customerId,
        customerEmail: input.customerEmail,
        action: input.action,
        ip: input.ip ?? null,
      },
    });
  } catch (e) {
    // Audit yazımı erişimi engellememeli ama sessizce de yutulmamalı — logla (secret YOK).
    console.error('[reportAudit] audit yazımı başarısız:', (e as Error).message);
  }
}
