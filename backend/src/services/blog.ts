import MarkdownIt from 'markdown-it';
import { prisma } from '../db.js';
import { guessCategory } from './blogCategories.js';
import { assignCover } from './blogImages.js';

/**
 * SEO otomatik blog — DB tabanli (git-commit YOK).
 * Admin toplu (front-matter) yukler -> draft. Worker gunde 1 en eski draft'i published yapar.
 */

// --- Slug normalize (GUVENLIK AGI) --------------------------------------------
// Turkce karakter -> ascii; kucuk harf; bosluk->tire; izin verilmeyen karakter temizlenir.
const TR_MAP: Record<string, string> = {
  ç: 'c', Ç: 'c', ğ: 'g', Ğ: 'g', ı: 'i', İ: 'i', ö: 'o', Ö: 'o', ş: 's', Ş: 's', ü: 'u', Ü: 'u',
  â: 'a', Â: 'a', î: 'i', Î: 'i', û: 'u', Û: 'u',
};
export function slugify(input: string): string {
  return (input || '')
    .trim()
    .replace(/[çÇğĞıİöÖşŞüÜâÂîÎûÛ]/g, (c) => TR_MAP[c] ?? c)
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '') // kalan aksanlari at
    .replace(/[^a-z0-9\s-]/g, '') // yalniz harf/rakam/bosluk/tire
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 120);
}

// --- Front-matter (coklu makale) ayristirici ----------------------------------
export interface ParsedArticle {
  title: string;
  description: string;
  slug: string;
  contentMd: string;
}

function parseFrontMatter(yaml: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of yaml.split('\n')) {
    const m = line.match(/^\s*([a-zA-Z_]+)\s*:\s*(.*)\s*$/);
    if (m) out[m[1].toLowerCase()] = m[2].trim().replace(/^["']|["']$/g, '').trim();
  }
  return out;
}

/**
 * `---\n<yaml>\n---\n<icerik>` bloklarindan olusan (birden fazla makale ard arda) metni parse
 * eder. Bir bloktan sonraki icerik, bir sonraki front-matter'a KADAR o makaleye aittir. Yalniz
 * title/slug iceren front-matter bloklari makale sayilir (markdown icindeki `---` hr'leri elenir).
 */
export function parseArticles(text: string): { articles: ParsedArticle[]; errors: string[] } {
  const src = (text || '').replace(/\r\n/g, '\n');
  const FM = /^---[ \t]*\n([\s\S]*?)\n---[ \t]*\n?/gm;
  const blocks: Array<{ fields: Record<string, string>; start: number; contentStart: number }> = [];
  let m: RegExpExecArray | null;
  while ((m = FM.exec(src))) {
    const fields = parseFrontMatter(m[1]);
    if (fields.title || fields.slug) blocks.push({ fields, start: m.index, contentStart: FM.lastIndex });
  }
  const articles: ParsedArticle[] = [];
  const errors: string[] = [];
  for (let i = 0; i < blocks.length; i++) {
    const content = src.slice(blocks[i].contentStart, i + 1 < blocks.length ? blocks[i + 1].start : src.length).trim();
    const f = blocks[i].fields;
    const title = (f.title || '').trim();
    const description = (f.description || '').trim();
    const slug = slugify(f.slug || title); // slug yoksa/bozuksa basliktan turet + normalize (guvenlik agi)
    if (!title) { errors.push(`#${i + 1}: 'title' eksik.`); continue; }
    if (!slug) { errors.push(`#${i + 1} ("${title}"): geçerli slug üretilemedi.`); continue; }
    if (!content) { errors.push(`#${i + 1} ("${title}"): içerik boş.`); continue; }
    articles.push({ title, description, slug, contentMd: content });
  }
  return { articles, errors };
}

// --- Dil normalize (cok-dilli blog) -------------------------------------------
// Desteklenen blog dilleri: tr (varsayilan) ve de. Bilinmeyen -> tr.
export const BLOG_LANGS = ['tr', 'de', 'en'] as const;
export function normalizeBlogLang(v: unknown): string {
  return typeof v === 'string' && (BLOG_LANGS as readonly string[]).includes(v) ? v : 'tr';
}

// --- Markdown -> HTML (icerik admin-uretimi; html:false ile ham HTML kacilir) -
const md = new MarkdownIt({ html: false, linkify: true, typographer: true });
export function renderContentHtml(contentMd: string): string {
  return md.render(contentMd || '');
}

// --- (TR KALITE KAPISI) Eksik Turkce karakter uyarisi ------------------------
// KOK NEDEN: slugify YALNIZ slug'a uygulanir; baslik/aciklama oldugu gibi kaydedilir.
// Yani gecmiste bozulan makaleler KOD hatasi degil, KAYNAK METNIN ASCII yazilmasiydi
// ("Guvenligi", "Basliklari", "Yapilandirma"...). Slug'in ASCII olmasi DOGRU ve korunur;
// bozulmamasi gereken GORUNEN metindir. Bu kapi, yeni yuklemelerde ayni hatayi yakalar
// (engellemez, admin'e UYARI dondurur) ki hatali baslik sessizce yayina girmesin.
const TR_DEDIACRITIZED = /\b(Guvenli\w*|guvenli\w*|Basliklar\w*|basliklar\w*|Yapilandirma\w*|yapilandirma\w*|Uygulamalarinda|Sureclerinde|Edilmis|edilmis|Taramasi|taramasi|nasil|Nasil|yapilir|sizma|asiri|ifsasi|aciklar\w*|kayitlar\w*|gecirilir|loglari|yonlendirme|kapatilir|duzeltme|suren|pahali|calisir|unuttugu|Sirketler\w*|hazirlik|yuzey|degerlendirme\w*)\b/g;

/** TR baslik/aciklamada diyakritigi dusmus kelimeleri dondurur (bos dizi = temiz). */
export function findDediacritizedTr(title: string, description: string): string[] {
  const hits = new Set<string>();
  for (const v of [title, description]) for (const m of String(v || '').matchAll(TR_DEDIACRITIZED)) hits.add(m[0]);
  return [...hits];
}

// --- Toplu taslak olusturma ---------------------------------------------------
export async function createDraftsFromBulk(text: string, lang = 'tr'): Promise<{
  created: Array<{ title: string; slug: string }>;
  conflicts: string[];
  errors: string[];
}> {
  const { articles, errors } = parseArticles(text);
  // (TR KALITE KAPISI) Eksik Turkce karakterli baslik/aciklama sessizce yayina girmesin.
  // Engellemez; admin ekranina UYARI olarak duser (slug ASCII kalmaya devam eder).
  if (lang === 'tr') {
    for (const a of articles) {
      const hits = findDediacritizedTr(a.title, a.description);
      if (hits.length) errors.push(`UYARI — "${a.title}": eksik Türkçe karakter olabilir (${hits.slice(0, 6).join(', ')}). Başlık/açıklamayı düzeltin; slug ASCII kalmalı.`);
    }
  }
  const conflicts: string[] = [];
  const created: Array<{ title: string; slug: string }> = [];
  const seenInBatch = new Set<string>();
  for (const a of articles) {
    if (seenInBatch.has(a.slug)) { conflicts.push(`"${a.title}" (${a.slug}) — bu yüklemede tekrar eden slug.`); continue; }
    // Cakisma kontrolu dil-bazli: ayni slug baska dilde olabilir, ayni dilde olamaz.
    const exists = await prisma.blogPost.findUnique({ where: { slug_lang: { slug: a.slug, lang } }, select: { id: true } });
    if (exists) { conflicts.push(`"${a.title}" (${a.slug}) — slug zaten mevcut (${lang}).`); continue; }
    seenInBatch.add(a.slug);
    // İçerikten DETERMİNİSTİK kategori tahmini (LLM yok) — yayında kapak eşleştirmesi için.
    await prisma.blogPost.create({ data: { title: a.title, description: a.description, slug: a.slug, contentMd: a.contentMd, status: 'draft', lang, category: guessCategory(a.title, a.contentMd) } });
    created.push({ title: a.title, slug: a.slug });
  }
  return { created, conflicts, errors };
}

// --- Yayinlama ----------------------------------------------------------------
/** En eski (ilk olusturulan) draft'i published yapar. lang verilirse yalniz o dilde. Sira bossa null. */
export async function publishNextDraft(lang?: string): Promise<{ slug: string; title: string } | null> {
  const draft = await prisma.blogPost.findFirst({
    where: { status: 'draft', ...(lang ? { lang } : {}) },
    orderBy: { createdAt: 'asc' },
  });
  if (!draft) return null;
  // Kategori boşsa (eski draft) yayında içerikten tahmin et — kapak ataması doğru kategoriden olsun.
  const category = draft.category ?? guessCategory(draft.title, draft.contentMd);
  await prisma.blogPost.update({ where: { id: draft.id }, data: { status: 'published', publishedAt: new Date(), category } });
  // Kapak görseli ata (kategori eşleşen görsellerden LRU+rastgele; yoksa herhangi biri). Best-effort.
  await assignCover(draft.id).catch(() => {});
  return { slug: draft.slug, title: draft.title };
}

/** TR gununun basi (UTC+3, DST yok) — "bugun" penceresi icin. */
function trDayStart(now = new Date()): Date {
  const tr = new Date(now.getTime() + 3 * 3600 * 1000);
  return new Date(Date.UTC(tr.getUTCFullYear(), tr.getUTCMonth(), tr.getUTCDate()) - 3 * 3600 * 1000);
}

/**
 * GUNDE 1 GARANTI: bugun (TR) zaten yayinlanmis bir makale yoksa en eski draft'i yayinla.
 * Worker her tick'te cagirir; restart-guvenli, cift-yayin YOK. Sira bossa sessizce gecer.
 */
export async function publishDailyIfDue(): Promise<void> {
  // Otomatik gunluk yayin HER GORUNUR BOLGE icin 1 makale: tr + de + en (SEO otomasyonu, 3 dilde).
  // Bir dilde bugun zaten yayin varsa o dil atlanir; sira bossa sessizce gecer. Restart-guvenli.
  const dayStart = trDayStart();
  for (const lang of ['tr', 'de', 'en']) {
    const publishedToday = await prisma.blogPost.count({
      where: { status: 'published', lang, publishedAt: { gte: dayStart } },
    });
    if (publishedToday > 0) continue; // bu dilde bugun zaten yayinlandi
    const done = await publishNextDraft(lang);
    if (done) console.log(`[blog] otomatik yayinlandi (${lang}): ${done.slug}`);
  }
}

// --- Okuma (public + admin) ---------------------------------------------------
export async function listPublished(lang = 'tr') {
  return prisma.blogPost.findMany({
    where: { status: 'published', lang },
    orderBy: { publishedAt: 'desc' },
    select: { title: true, description: true, slug: true, publishedAt: true, coverImageId: true, category: true },
  });
}

export async function getPublishedBySlug(slug: string, lang = 'tr') {
  const post = await prisma.blogPost.findFirst({
    where: { slug, lang, status: 'published' },
    select: { title: true, description: true, slug: true, contentMd: true, publishedAt: true, coverImageId: true, category: true },
  });
  if (!post) return null;
  return { ...post, contentHtml: renderContentHtml(post.contentMd) };
}

export async function listAllAdmin(lang?: string) {
  const posts = await prisma.blogPost.findMany({
    where: lang ? { lang } : {},
    orderBy: [{ status: 'asc' }, { createdAt: 'asc' }],
    select: { id: true, title: true, slug: true, status: true, lang: true, createdAt: true, publishedAt: true, category: true, coverImageId: true, coverManual: true },
  });
  const draftCount = posts.filter((p) => p.status === 'draft').length;
  const publishedCount = posts.filter((p) => p.status === 'published').length;
  const lastPublishedAt = posts
    .filter((p) => p.publishedAt)
    .map((p) => p.publishedAt as Date)
    .sort((a, b) => b.getTime() - a.getTime())[0] ?? null;
  return { posts, draftCount, publishedCount, lastPublishedAt };
}

// --- Taslak yönetimi (SERT KURAL: YALNIZ taslak; yayınlanmışa DOKUNMA) ---------
/** Taslağı sil. status='published' ise REDDEDER (geri alınamaz + trafik/backlink gider). */
export async function deleteDraft(id: string): Promise<{ ok: true; deleted: { title: string; slug: string } } | { ok: false; reason: string }> {
  const post = await prisma.blogPost.findUnique({ where: { id }, select: { title: true, slug: true, status: true } });
  if (!post) return { ok: false, reason: 'Bulunamadı.' };
  if (post.status === 'published') return { ok: false, reason: 'Yayınlanmış içerik silinemez (yalnız taslak).' };
  await prisma.blogPost.delete({ where: { id } });
  return { ok: true, deleted: { title: post.title, slug: post.slug } };
}

/** Taslağı düzenle (title/description/contentMd/category). Yayınlanmışsa REDDEDER. */
export async function updateDraft(id: string, patch: { title?: string; description?: string; contentMd?: string; category?: string }): Promise<{ ok: boolean; reason?: string }> {
  const post = await prisma.blogPost.findUnique({ where: { id }, select: { status: true, title: true, contentMd: true } });
  if (!post) return { ok: false, reason: 'Bulunamadı.' };
  if (post.status === 'published') return { ok: false, reason: 'Yayınlanmış içerik düzenlenemez (yalnız taslak).' };
  const data: Record<string, unknown> = {};
  if (typeof patch.title === 'string' && patch.title.trim()) data.title = patch.title.trim();
  if (typeof patch.description === 'string') data.description = patch.description.trim();
  if (typeof patch.contentMd === 'string' && patch.contentMd.trim()) {
    data.contentMd = patch.contentMd;
    // İçerik değiştiyse kategoriyi (patch'te yoksa) yeniden tahmin et.
    if (!patch.category) data.category = guessCategory((patch.title ?? post.title), patch.contentMd);
  }
  if (typeof patch.category === 'string' && patch.category) data.category = patch.category;
  if (Object.keys(data).length === 0) return { ok: false, reason: 'Değişiklik yok.' };
  await prisma.blogPost.update({ where: { id }, data });
  return { ok: true };
}

/**
 * İçerik yükleyici (toplu üretim için). (slug,lang) anahtarına göre:
 *  - kayıt YOKSA → taslak oluştur
 *  - varsa ve TASLAK → içeriği güncelle (skeleton→tam genişletme)
 *  - varsa ve YAYINLANMIŞ → DOKUNMA, 'skipped-published' dön (SERT KURAL)
 * Kategori verilmezse içerikten tahmin edilir.
 */
export async function upsertDraft(a: { slug: string; lang: string; title: string; description: string; contentMd: string; category?: string }):
  Promise<'created' | 'updated' | 'skipped-published'> {
  const lang = normalizeBlogLang(a.lang);
  const slug = slugify(a.slug || a.title);
  const category = a.category ?? guessCategory(a.title, a.contentMd);
  const existing = await prisma.blogPost.findUnique({ where: { slug_lang: { slug, lang } }, select: { id: true, status: true } });
  if (existing) {
    if (existing.status === 'published') return 'skipped-published'; // ASLA dokunma
    await prisma.blogPost.update({ where: { id: existing.id }, data: { title: a.title, description: a.description, contentMd: a.contentMd, category } });
    return 'updated';
  }
  await prisma.blogPost.create({ data: { title: a.title, description: a.description, slug, contentMd: a.contentMd, status: 'draft', lang, category } });
  return 'created';
}
