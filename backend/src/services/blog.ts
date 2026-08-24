import MarkdownIt from 'markdown-it';
import { prisma } from '../db.js';

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

// --- Toplu taslak olusturma ---------------------------------------------------
export async function createDraftsFromBulk(text: string, lang = 'tr'): Promise<{
  created: Array<{ title: string; slug: string }>;
  conflicts: string[];
  errors: string[];
}> {
  const { articles, errors } = parseArticles(text);
  const conflicts: string[] = [];
  const created: Array<{ title: string; slug: string }> = [];
  const seenInBatch = new Set<string>();
  for (const a of articles) {
    if (seenInBatch.has(a.slug)) { conflicts.push(`"${a.title}" (${a.slug}) — bu yüklemede tekrar eden slug.`); continue; }
    // Cakisma kontrolu dil-bazli: ayni slug baska dilde olabilir, ayni dilde olamaz.
    const exists = await prisma.blogPost.findUnique({ where: { slug_lang: { slug: a.slug, lang } }, select: { id: true } });
    if (exists) { conflicts.push(`"${a.title}" (${a.slug}) — slug zaten mevcut (${lang}).`); continue; }
    seenInBatch.add(a.slug);
    await prisma.blogPost.create({ data: { title: a.title, description: a.description, slug: a.slug, contentMd: a.contentMd, status: 'draft', lang } });
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
  await prisma.blogPost.update({ where: { id: draft.id }, data: { status: 'published', publishedAt: new Date() } });
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
  // Otomatik gunluk yayin YALNIZ tr (SEO otomasyonu). Almanca yazilari kullanici admin'den ELLE
  // yayinlar (P5: "tek tek yukleyecek") — otomatik yayina girmezler.
  const publishedToday = await prisma.blogPost.count({
    where: { status: 'published', lang: 'tr', publishedAt: { gte: trDayStart() } },
  });
  if (publishedToday > 0) return; // bugun zaten yayinlandi
  const done = await publishNextDraft('tr');
  if (done) console.log(`[blog] otomatik yayinlandi: ${done.slug}`);
}

// --- Okuma (public + admin) ---------------------------------------------------
export async function listPublished(lang = 'tr') {
  return prisma.blogPost.findMany({
    where: { status: 'published', lang },
    orderBy: { publishedAt: 'desc' },
    select: { title: true, description: true, slug: true, publishedAt: true },
  });
}

export async function getPublishedBySlug(slug: string, lang = 'tr') {
  const post = await prisma.blogPost.findFirst({
    where: { slug, lang, status: 'published' },
    select: { title: true, description: true, slug: true, contentMd: true, publishedAt: true },
  });
  if (!post) return null;
  return { ...post, contentHtml: renderContentHtml(post.contentMd) };
}

export async function listAllAdmin(lang?: string) {
  const posts = await prisma.blogPost.findMany({
    where: lang ? { lang } : {},
    orderBy: [{ status: 'asc' }, { createdAt: 'asc' }],
    select: { id: true, title: true, slug: true, status: true, lang: true, createdAt: true, publishedAt: true },
  });
  const draftCount = posts.filter((p) => p.status === 'draft').length;
  const publishedCount = posts.filter((p) => p.status === 'published').length;
  const lastPublishedAt = posts
    .filter((p) => p.publishedAt)
    .map((p) => p.publishedAt as Date)
    .sort((a, b) => b.getTime() - a.getTime())[0] ?? null;
  return { posts, draftCount, publishedCount, lastPublishedAt };
}
