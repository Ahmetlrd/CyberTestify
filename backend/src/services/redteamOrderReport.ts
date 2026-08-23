/**
 * (S1 TİCARİ ENTEGRASYON — Aşama 2) Otonom Red Team koşusu (RedTeamJob) tamamlanınca, ödemeli Order'a
 * bağlıysa raporu MEVCUT 6-paket teslim makinesiyle (Report modeli) uyumlu biçimde saklar:
 *  - İçerik = RedTeamReport JSON, müşteri erişim koduyla AES-256-GCM ŞİFRELİ (encryptReport).
 *  - devAccessSecret = pepper ile şifreli erişim kodu (admin onayda decryptSecret ile açıp e-postalar).
 *  - Order → awaiting_admin_review (config.adminReportGate açıksa) → mevcut approve-report + sendReportReady
 *    zinciri AYNEN devreye girer. Kapı kapalıysa scan_completed (çağıran e-postayı gönderir).
 * İndirme (reports.ts) redteam_s1 order'da bu JSON'u çözüp renderRedTeamFullHtml(r,'customer') ile PDF'e çevirir.
 * report.ts (6-paket motoru) DEĞİŞMEZ — ayrı, küçük köprü modülü.
 */
import { prisma } from '../db.js';
import { config } from '../config.js';
import { encryptReport, generateReportAccessSecret, encryptSecret } from './crypto.js';

export async function storeRedTeamCustomerReport(
  orderId: string,
  redTeamReport: unknown,
  opts: { incomplete?: boolean; incompleteReason?: string | null } = {},
): Promise<{ accessSecret: string; gated: boolean }> {
  const accessSecret = generateReportAccessSecret();
  const payload = Buffer.from(JSON.stringify(redTeamReport ?? {}), 'utf-8');
  const enc = encryptReport(payload, accessSecret);

  const blobFields = {
    encryptedBlob: enc.encryptedBlob,
    iv: enc.iv,
    authTag: enc.authTag,
    keyDerivationSalt: enc.keyDerivationSalt,
    devAccessSecret: encryptSecret(accessSecret), // pepper-encrypted; admin onayda açılır
    incomplete: opts.incomplete ?? false,
    incompleteReason: opts.incompleteReason ?? null,
  };

  // orderId @unique → upsert idempotent (yeniden koşu: yeni kod+blob, onay sıfırlanır).
  await prisma.report.upsert({
    where: { orderId },
    create: { orderId, ...blobFields },
    update: { ...blobFields, adminReleasedAt: null, deliveredAt: null },
  });

  const gated = config.adminReportGate;
  await prisma.order.update({
    where: { id: orderId },
    data: { status: gated ? 'awaiting_admin_review' : 'scan_completed' },
  });
  return { accessSecret, gated };
}
