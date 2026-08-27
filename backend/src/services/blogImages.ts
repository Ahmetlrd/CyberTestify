import { prisma } from '../db.js';
import { isValidCategory } from './blogCategories.js';

/**
 * (BLOG GÖRSEL KÜTÜPHANESİ) Kategori-etiketli görsellerin CRUD'u + yayında kapak ataması.
 * Bayt DB'de (BlogImage.data BYTEA). Yükleme öncesi tarayıcıda WebP'ye dönüştürülür (bkz Fotolar sayfası);
 * burada yalnız base64 çözülüp saklanır. Kapak seçimi LRU+rastgele (çeşitlilik): kategori içi en az/eski
 * kullanılan birkaç adaydan rastgele biri → aynı görsel her makalede tekrar etmesin.
 */

const MAX_BYTES = Math.floor(3.5 * 1024 * 1024); // ~3.5MB ham (WebP+resize sonrası çok altında; güvenlik sınırı)

export type BlogImageMeta = {
  id: string; category: string; mime: string; width: number | null; height: number | null;
  alt: string | null; usedCount: number; lastUsedAt: Date | null; createdAt: Date;
};

const META_SELECT = {
  id: true, category: true, mime: true, width: true, height: true,
  alt: true, usedCount: true, lastUsedAt: true, createdAt: true,
} as const;

/** base64 (data URI veya çıplak) → Buffer; boyut/format doğrulama. */
export function decodeImage(dataBase64: string): { buf: Buffer; mime: string } {
  const m = /^data:([a-z0-9/+.\-]+);base64,(.*)$/is.exec(dataBase64.trim());
  const mime = (m ? m[1] : 'image/webp').toLowerCase();
  const b64 = m ? m[2] : dataBase64.trim();
  if (!/^image\/(webp|png|jpe?g|avif|gif)$/.test(mime)) throw new Error('Yalnız görsel (webp/png/jpg/avif/gif) yüklenebilir.');
  const buf = Buffer.from(b64, 'base64');
  if (!buf.length) throw new Error('Görsel verisi boş/çözülemedi.');
  if (buf.length > MAX_BYTES) throw new Error(`Görsel çok büyük (${Math.round(buf.length / 1024)}KB). Tarayıcıda küçültülmeliydi.`);
  return { buf, mime };
}

export async function createImage(input: {
  category: string; dataBase64: string; width?: number; height?: number; alt?: string;
}): Promise<BlogImageMeta> {
  if (!isValidCategory(input.category)) throw new Error('Geçersiz kategori.');
  const { buf, mime } = decodeImage(input.dataBase64);
  return prisma.blogImage.create({
    data: {
      category: input.category, mime, data: buf,
      width: input.width ?? null, height: input.height ?? null,
      alt: input.alt?.trim() || null,
    },
    select: META_SELECT,
  });
}

export async function listImages(category?: string): Promise<BlogImageMeta[]> {
  return prisma.blogImage.findMany({
    where: category && isValidCategory(category) ? { category } : {},
    orderBy: [{ category: 'asc' }, { createdAt: 'desc' }],
    select: META_SELECT,
  });
}

export async function getImageBytes(id: string): Promise<{ data: Buffer; mime: string } | null> {
  const img = await prisma.blogImage.findUnique({ where: { id }, select: { data: true, mime: true } });
  if (!img) return null;
  return { data: Buffer.from(img.data), mime: img.mime };
}

export async function deleteImage(id: string): Promise<void> {
  await prisma.blogImage.delete({ where: { id } }).catch(() => {});
  // Bu görseli kapak olarak kullanan makalelerin coverImageId'sini temizle (kırık kapak kalmasın).
  await prisma.blogPost.updateMany({ where: { coverImageId: id }, data: { coverImageId: null, coverManual: false } });
}

/**
 * Kategoriye göre bir görsel seç (LRU + rastgele). Kategoride hiç yoksa HERHANGİ bir görselden seçer
 * (kullanıcı tercihi: makale kapaksız kalmasın). Kütüphane tamamen boşsa null.
 * Seçilen görselin lastUsedAt/usedCount'u güncellenir (bir dahaki sefere daha az tercih edilsin → çeşitlilik).
 */
export async function pickImageForCategory(category: string | null | undefined): Promise<string | null> {
  const inCat = category && isValidCategory(category)
    ? await prisma.blogImage.findMany({ where: { category }, orderBy: [{ lastUsedAt: 'asc' }, { usedCount: 'asc' }], take: 5, select: { id: true } })
    : [];
  let pool = inCat;
  if (pool.length === 0) {
    // Fallback: herhangi bir kategoriden en az kullanılan birkaç aday.
    pool = await prisma.blogImage.findMany({ orderBy: [{ lastUsedAt: 'asc' }, { usedCount: 'asc' }], take: 5, select: { id: true } });
  }
  if (pool.length === 0) return null; // kütüphane boş
  const chosen = pool[Math.floor(Math.random() * pool.length)].id;
  await prisma.blogImage.update({ where: { id: chosen }, data: { usedCount: { increment: 1 }, lastUsedAt: new Date() } }).catch(() => {});
  return chosen;
}

/**
 * Bir makaleye kapak ata (yayında çağrılır). coverManual=true ise (admin elle seçmiş) DOKUNMA.
 * force=true ise mevcut kapağı da yeniden seçer (admin "yeniden çek" için).
 */
export async function assignCover(postId: string, opts: { force?: boolean } = {}): Promise<string | null> {
  const post = await prisma.blogPost.findUnique({ where: { id: postId }, select: { category: true, coverImageId: true, coverManual: true } });
  if (!post) return null;
  if (!opts.force && (post.coverManual || post.coverImageId)) return post.coverImageId; // zaten var / elle seçilmiş
  const chosen = await pickImageForCategory(post.category);
  if (!chosen) return post.coverImageId ?? null;
  await prisma.blogPost.update({ where: { id: postId }, data: { coverImageId: chosen, coverManual: false } });
  return chosen;
}

/** Admin override: belirli bir görseli kapak yap (coverManual=true → otomatik yeniden-atama olmaz). */
export async function setCoverManual(postId: string, imageId: string): Promise<void> {
  const img = await prisma.blogImage.findUnique({ where: { id: imageId }, select: { id: true } });
  if (!img) throw new Error('Görsel bulunamadı.');
  await prisma.blogPost.update({ where: { id: postId }, data: { coverImageId: imageId, coverManual: true } });
}
