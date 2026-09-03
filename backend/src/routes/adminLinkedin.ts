/**
 * (LINKEDIN OTOMATIK PAYLASIM) Admin paneli endpoint'leri — Buffer GraphQL API uzerinden.
 *
 * IZOLE bir ozelliktir: tarama motoru / paket / fiyat / rapor / S1 akislarina DOKUNMAZ.
 * Tum uclar '/admin' altinda mount edilir -> requireAdmin + IP allowlist + rate limit zaten uygulanir.
 * SESSIZ HATA YOK: Buffer'a giden her istek basarisiz olursa kayit FAILED + errorMessage ile saklanir.
 */
import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../db.js';
import { renderCarouselPdf, renderSlidePng, type Slide } from '../services/linkedinCarousel.js';
import { config } from '../config.js';
import {
  bufferEnabled,
  resolveLinkedInTarget,
  scheduleLinkedInPost,
  deleteBufferPost,
  getBufferPost,
  BufferError,
} from '../services/bufferClient.js';

export const adminLinkedinRouter = Router();

const MAX_LEN = 3000; // LinkedIn gonderi metni ust siniri

function msgOf(e: unknown): string {
  if (e instanceof BufferError) return e.message;
  return 'Buffer isteği tamamlanamadı.';
}

/** Buffer durum -> bizim durum. Buffer PostStatus: draft|error|needs_approval|scheduled|sending|sent */
function mapBufferStatus(bufferStatus: string | null, fallback: string): string {
  switch (bufferStatus) {
    case 'sent': return 'PUBLISHED';
    case 'error': return 'FAILED';
    case 'draft': return 'DRAFT';
    case 'scheduled':
    case 'sending':
    case 'needs_approval': return fallback === 'SCHEDULED' ? 'SCHEDULED' : 'QUEUED';
    default: return fallback;
  }
}

// --- Baglanti durumu: kanal bagli mi, anahtar var mi ------------------------------------------
adminLinkedinRouter.get('/status', async (_req, res) => {
  if (!bufferEnabled()) {
    return res.json({ enabled: false, error: 'BUFFER_API_KEY tanımlı değil — sunucu .env dosyasına ekleyin.' });
  }
  try {
    const t = await resolveLinkedInTarget();
    // NOT: organizationId/channelId hassas sir DEGIL; API anahtari ASLA donmez.
    res.json({ enabled: true, channelId: t.channelId, channelName: t.channelName, organizationId: t.organizationId });
  } catch (e) {
    res.json({ enabled: false, error: msgOf(e) });
  }
});

// --- MEDYA (PDF carousel / gorsel) -------------------------------------------------------------
// Slaytlar SUNUCUDA render edilir (puppeteer-core, zaten kurulu) -> bayt DB'ye yazilir -> PUBLIC
// /linkedin-assets/:id URL'i Buffer'a verilir. Musterinin elle dosya uretmesi/yuklemesi GEREKMEZ.
const slideSchema = z.object({
  kicker: z.string().trim().max(40).optional(),
  title: z.string().trim().min(1).max(160),
  body: z.string().trim().max(600).optional(),
  bullets: z.array(z.string().trim().min(1).max(220)).max(7).optional(),
  variant: z.enum(['cover', 'content', 'cta']).optional(),
});
const carouselSchema = z.object({
  title: z.string().trim().min(1).max(120), // LinkedIn dokuman basligi (carousel ustunde gorunur)
  slides: z.array(slideSchema).min(2).max(14),
});

/** Public URL — Buffer/LinkedIn bu adresten ceker. */
function assetUrl(id: string): string {
  return `${config.publicApiUrl.replace(/\/+$/, '')}/linkedin-assets/${id}`;
}

adminLinkedinRouter.post('/assets/carousel', async (req, res) => {
  const parsed = carouselSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  try {
    const slides = parsed.data.slides as Slide[];
    const pdf = await renderCarouselPdf(slides);
    // Buffer DocumentAssetInput.thumbnailUrl ZORUNLU -> kapak slaytindan PNG uretilip ayri asset olur.
    const thumb = await renderSlidePng(slides[0]);
    const th = await prisma.linkedinAsset.create({
      data: { kind: 'image', mime: 'image/png', title: `${parsed.data.title} (kapak)`, data: thumb, bytes: thumb.length },
      select: { id: true },
    });
    const a = await prisma.linkedinAsset.create({
      data: { kind: 'pdf', mime: 'application/pdf', title: parsed.data.title, data: pdf, bytes: pdf.length, pages: slides.length, thumbnailId: th.id },
      select: { id: true, bytes: true, pages: true },
    });
    res.status(201).json({ ok: true, id: a.id, url: assetUrl(a.id), thumbnailUrl: assetUrl(th.id), bytes: a.bytes, pages: a.pages });
  } catch (e) {
    res.status(500).json({ error: `PDF üretilemedi: ${(e as Error).message}` });
  }
});

adminLinkedinRouter.post('/assets/image', async (req, res) => {
  const parsed = z.object({ title: z.string().trim().min(1).max(120), slide: slideSchema }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  try {
    const png = await renderSlidePng(parsed.data.slide as Slide);
    const a = await prisma.linkedinAsset.create({
      data: { kind: 'image', mime: 'image/png', title: parsed.data.title, data: png, bytes: png.length },
      select: { id: true, bytes: true },
    });
    res.status(201).json({ ok: true, id: a.id, url: assetUrl(a.id), bytes: a.bytes });
  } catch (e) {
    res.status(500).json({ error: `Görsel üretilemedi: ${(e as Error).message}` });
  }
});

adminLinkedinRouter.get('/assets', async (_req, res) => {
  const items = await prisma.linkedinAsset.findMany({
    orderBy: { createdAt: 'desc' }, take: 100,
    select: { id: true, kind: true, title: true, bytes: true, pages: true, createdAt: true },
  });
  res.json({ items: items.map((a) => ({ ...a, url: assetUrl(a.id) })) });
});

// --- Liste: zamanlanmislar + arsiv -------------------------------------------------------------
adminLinkedinRouter.get('/posts', async (req, res) => {
  const status = typeof req.query.status === 'string' ? req.query.status : '';
  const where = status ? { status } : {};
  const items = await prisma.linkedinPost.findMany({ where, orderBy: { createdAt: 'desc' }, take: 200 });
  const pendingCount = await prisma.linkedinPost.count({ where: { status: { in: ['QUEUED', 'SCHEDULED'] } } });
  res.json({ items, pendingCount });
});

// --- Olustur: siraya ekle | belirli tarihte paylas ---------------------------------------------
const createSchema = z.object({
  content: z.string().trim().min(1, 'Metin boş olamaz.').max(MAX_LEN),
  mediaUrl: z.string().trim().url('Görsel URL geçersiz.').optional().or(z.literal('')),
  /** (NATIF CAROUSEL) /assets/carousel'den dönen PDF asset id'si — LinkedIn kaydırılabilir gösterir. */
  documentAssetId: z.string().uuid().optional().or(z.literal('')),
  /** (GÖRSEL) /assets/image'dan dönen PNG asset id'si — mediaUrl yerine kullanılabilir. */
  imageAssetId: z.string().uuid().optional().or(z.literal('')),
  mode: z.enum(['addToQueue', 'customScheduled']),
  scheduledFor: z.string().datetime({ offset: true }).optional().or(z.literal('')),
});

adminLinkedinRouter.post('/posts', async (req, res) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const { content, mode } = parsed.data;
  // Asset id verildiyse PUBLIC url'e çevrilir; doğrudan mediaUrl da desteklenir (geri uyumluluk).
  let docUrl: string | null = null;
  let docTitle: string | null = null;
  let docThumb: string | null = null;
  if (parsed.data.documentAssetId) {
    const a = await prisma.linkedinAsset.findUnique({ where: { id: parsed.data.documentAssetId }, select: { id: true, kind: true, title: true, thumbnailId: true } });
    if (!a || a.kind !== 'pdf') return res.status(400).json({ error: 'PDF medyası bulunamadı.' });
    if (!a.thumbnailId) return res.status(400).json({ error: 'PDF kapak görseli eksik (yeniden üretin).' });
    docUrl = assetUrl(a.id); docTitle = a.title; docThumb = assetUrl(a.thumbnailId);
  }
  let mediaUrl = parsed.data.mediaUrl || null;
  if (!mediaUrl && parsed.data.imageAssetId) {
    const a = await prisma.linkedinAsset.findUnique({ where: { id: parsed.data.imageAssetId }, select: { id: true, kind: true } });
    if (!a || a.kind !== 'image') return res.status(400).json({ error: 'Görsel medyası bulunamadı.' });
    mediaUrl = assetUrl(a.id);
  }
  const scheduledFor = parsed.data.scheduledFor ? new Date(parsed.data.scheduledFor) : null;

  if (mode === 'customScheduled') {
    if (!scheduledFor) return res.status(400).json({ error: 'Belirli tarihte paylaşım için tarih/saat seçin.' });
    if (scheduledFor.getTime() < Date.now() + 60_000) {
      return res.status(400).json({ error: 'Tarih/saat gelecekte olmalı.' });
    }
  }

  // Once DB'ye yaz (DRAFT) -> Buffer cagrisi ne olursa olsun kayit KAYBOLMAZ; hata da gorunur olur.
  const row = await prisma.linkedinPost.create({
    data: { content, mediaUrl: docUrl ?? mediaUrl, status: 'DRAFT', scheduledFor },
  });

  try {
    const created = await scheduleLinkedInPost({
      text: content,
      mode,
      dueAt: scheduledFor ? scheduledFor.toISOString() : null,
      imageUrl: mediaUrl,
      documentUrl: docUrl,
      documentTitle: docTitle,
      documentThumbnailUrl: docThumb,
    });
    const updated = await prisma.linkedinPost.update({
      where: { id: row.id },
      data: {
        status: mode === 'customScheduled' ? 'SCHEDULED' : 'QUEUED',
        bufferPostId: created.id,
        scheduledFor: created.dueAt ? new Date(created.dueAt) : scheduledFor,
        errorMessage: null,
      },
    });
    res.status(201).json({ ok: true, post: updated });
  } catch (e) {
    const failed = await prisma.linkedinPost.update({
      where: { id: row.id },
      data: { status: 'FAILED', errorMessage: msgOf(e) },
    });
    // 200 DEGIL: admin panelinde hata olarak gorunsun; kayit yine de FAILED olarak listede.
    res.status(502).json({ error: failed.errorMessage, post: failed });
  }
});

// --- Iptal: once BUFFER'dan sil, sonra DB'den (yalniz DB'den silmek YETERSIZ) -------------------
adminLinkedinRouter.delete('/posts/:id', async (req, res) => {
  const row = await prisma.linkedinPost.findUnique({ where: { id: req.params.id } });
  if (!row) return res.status(404).json({ error: 'Gönderi bulunamadı.' });

  if (row.bufferPostId && row.status !== 'PUBLISHED') {
    try {
      await deleteBufferPost(row.bufferPostId);
    } catch (e) {
      // Buffer'da silinemediyse DB'den de SILME — aksi halde Buffer'da yayinlanip bizde iz kalmaz.
      const failed = await prisma.linkedinPost.update({
        where: { id: row.id },
        data: { status: 'FAILED', errorMessage: `İptal edilemedi: ${msgOf(e)}` },
      });
      return res.status(502).json({ error: failed.errorMessage, post: failed });
    }
  }
  await prisma.linkedinPost.delete({ where: { id: row.id } });
  res.json({ ok: true, deleted: true });
});

// --- Durum senkronu: bekleyen gonderilerin Buffer'daki guncel durumu ---------------------------
adminLinkedinRouter.post('/sync', async (_req, res) => {
  const pending = await prisma.linkedinPost.findMany({
    where: { status: { in: ['QUEUED', 'SCHEDULED'] }, bufferPostId: { not: null } },
    take: 100,
  });
  let updated = 0;
  for (const p of pending) {
    const remote = await getBufferPost(p.bufferPostId as string); // best-effort; null ise dokunma
    if (!remote) continue;
    const next = mapBufferStatus(remote.status, p.status);
    if (next !== p.status) {
      await prisma.linkedinPost.update({
        where: { id: p.id },
        data: { status: next, errorMessage: next === 'FAILED' ? 'Buffer gönderiyi yayınlayamadı.' : null },
      });
      updated++;
    }
  }
  res.json({ ok: true, checked: pending.length, updated });
});
