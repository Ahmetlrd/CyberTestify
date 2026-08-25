/**
 * (ADMIN 2FA KAÇIŞ KAPISI — SUNUCU TARAFI, panelden DEĞİL)
 *
 * Admin telefonunu VE kurtarma kodlarını kaybederse kendini kilitlemesin diye, YALNIZCA sunucuya
 * (DB'ye) erişimi olan biri bu komutu çalıştırıp o admin'in 2FA'sını sıfırlayabilir. Bir sonraki
 * girişte admin yeniden enrollment yapar (QR okut + yeni kurtarma kodları). Panel üzerinden 2FA
 * sıfırlama BİLEREK YOKTUR — olsaydı 2FA'nın anlamı kalmazdı.
 *
 * KULLANIM (sunucuda, uygulama container'ında):
 *   docker exec -it cybertestify-api npx tsx prisma/resetAdmin2fa.ts <admin-email>
 * veya doğrudan:
 *   npx tsx prisma/resetAdmin2fa.ts admin@ornek.com
 *
 * Etki: totpSecret, twofaEnabled, twofaConfirmedAt, twofaRecoveryCodes, kilit sayaçları temizlenir.
 */
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  const email = process.argv[2];
  if (!email) {
    console.error('Kullanım: npx tsx prisma/resetAdmin2fa.ts <admin-email>');
    process.exit(1);
  }
  const admin = await prisma.adminUser.findUnique({ where: { email } });
  if (!admin) {
    console.error(`Admin bulunamadı: ${email}`);
    process.exit(1);
  }
  await prisma.adminUser.update({
    where: { id: admin.id },
    data: {
      totpSecret: null,
      twofaEnabled: false,
      twofaConfirmedAt: null,
      twofaRecoveryCodes: null,
      twofaFailedAttempts: 0,
      twofaLockedUntil: null,
    },
  });
  console.log(`✅ 2FA sıfırlandı: ${email}. Bir sonraki girişte yeniden kurulum (enrollment) istenecek.`);
}

main()
  .catch((e) => { console.error(e); process.exit(1); })
  .finally(() => prisma.$disconnect());
