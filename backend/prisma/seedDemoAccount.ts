/**
 * iyzico incelemesi icin DEMO musteri hesabi + ONCEDEN dogrulanmis domain olusturur.
 * Bu hesapla giris yapan kisi tekrar DNS TXT dogrulamasi YAPMADAN dogrudan paket secip
 * odeme adimina gidebilir (yalniz bu demo hesap icin; gercek surec atlanmaz).
 *
 * Kullanim (sunucuda):
 *   docker exec cybertestify-api npx tsx prisma/seedDemoAccount.ts
 *   docker exec -e DEMO_EMAIL=... -e DEMO_PASSWORD='...' cybertestify-api npx tsx prisma/seedDemoAccount.ts
 * Idempotent: tekrar calisinca sifreyi + domain'i gunceller.
 */
import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import { prisma } from '../src/db.js';

async function main() {
  const email = (process.env.DEMO_EMAIL ?? 'iyzico-review@cybertestify.com').trim().toLowerCase();
  const password = process.env.DEMO_PASSWORD ?? 'IyzicoReview2026!';
  const hostname = (process.env.DEMO_DOMAIN ?? 'cybertestify.com').trim().toLowerCase();
  const resolvedIps = process.env.DEMO_IPS ?? '164.92.223.208';

  const passwordHash = await bcrypt.hash(password, 12);
  const customer = await prisma.customer.upsert({
    where: { email },
    update: { passwordHash, fullName: 'iyzico Review', termsAcceptedAt: new Date(), termsVersion: 'demo' },
    create: { email, passwordHash, fullName: 'iyzico Review', termsAcceptedAt: new Date(), termsVersion: 'demo' },
  });

  const domain = await prisma.domain.upsert({
    where: { customerId_hostname: { customerId: customer.id, hostname } },
    update: {
      status: 'verified', verifiedAt: new Date(), lastCheckedAt: new Date(),
      resolvedIps, hostingType: 'dedicated',
    },
    create: {
      customerId: customer.id, hostname,
      verificationToken: `pentest-verify=${crypto.randomBytes(12).toString('hex')}`,
      verificationMethod: 'dns_txt', status: 'verified', verifiedAt: new Date(), lastCheckedAt: new Date(),
      resolvedIps, hostingType: 'dedicated',
    },
  });

  console.log('=== DEMO HESAP HAZIR ===');
  console.log('E-posta :', email);
  console.log('Sifre   :', password);
  console.log('Domain  :', hostname, '(status=' + domain.status + ', ONCEDEN dogrulanmis)');
  console.log('Bu hesapla giris -> paket sec -> odeme adimi (tekrar dogrulama YOK).');
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
