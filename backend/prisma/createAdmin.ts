/**
 * Ilk (veya ek) admin kullanicisini olusturur/gunceller — MUSTERI kayit akisindan
 * BAGIMSIZ. Herkese acik register YOK; admin yalnizca bu CLI ile eklenir.
 *
 * Kullanim (sunucuda, api container'i icinde):
 *   docker exec -e ADMIN_EMAIL=vedat@... -e ADMIN_PASSWORD='...' \
 *     cybertestify-api npx tsx prisma/createAdmin.ts
 * veya argumanla:
 *   docker exec cybertestify-api npx tsx prisma/createAdmin.ts vedat@... 'sifre'
 *
 * Idempotent: ayni email varsa SIFREYI gunceller (sifirlama icin de kullanilir).
 */
import bcrypt from 'bcryptjs';
import { prisma } from '../src/db.js';

async function main() {
  const email = (process.argv[2] ?? process.env.ADMIN_EMAIL ?? '').trim().toLowerCase();
  const password = process.argv[3] ?? process.env.ADMIN_PASSWORD ?? '';

  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    console.error('HATA: gecerli bir email verin (arg1 veya ADMIN_EMAIL).');
    process.exit(1);
  }
  if (password.length < 10) {
    console.error('HATA: sifre en az 10 karakter olmali (arg2 veya ADMIN_PASSWORD).');
    process.exit(1);
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const admin = await prisma.adminUser.upsert({
    where: { email },
    update: { passwordHash },
    create: { email, passwordHash },
  });
  console.log(`[createAdmin] OK — admin ${admin.email} (id=${admin.id}) olusturuldu/guncellendi.`);
  process.exit(0);
}

main().catch((e) => {
  console.error('[createAdmin] HATA:', e?.message ?? e);
  process.exit(1);
});
