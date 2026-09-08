/**
 * (KAMPANYA OTOMATİK DOLDURMA) Buffer ÜCRETSİZ planı aynı anda EN FAZLA 10 zamanlanmış gönderiye
 * izin verir ("Scheduled posts limit reached. You have 10 scheduled posts out of 10 allowed.").
 * 14 gönderilik kampanya bu yüzden tek seferde kuyruğa GİRMEZ.
 *
 * Çözüm: worker her gün bu işi çağırır. Bir gönderi yayınlanıp slot boşaldıkça, kampanyadaki
 * SIRADAKİ gönderi otomatik olarak kuyruğa alınır. Kullanıcının hiçbir şey yapması gerekmez;
 * plan yükseltilirse de aynı kod fazladan slotu anında kullanır.
 *
 * IDEMPOTENT + restart-güvenli: zaten SCHEDULED/PUBLISHED olan atlanır, önceki FAILED kaydı
 * yeniden kullanılır (yinelenen satır birikmez).
 */
import { prisma } from '../db.js';
import { CAMPAIGN } from '../campaigns/linkedin2026_09.js';
import { renderCarouselPdf, renderSlidePng, type Slide } from './linkedinCarousel.js';
import { scheduleLinkedInPost, bufferEnabled, getBufferPost } from './bufferClient.js';
import { config } from '../config.js';

export const CAMPAIGN_TOPUP_INTERVAL_MS = 6 * 60 * 60 * 1000; // 6 saatte bir dener (gün içi slot açılırsa yakalar)

/** (DURUM SENKRONU) Buffer PostStatus (draft|error|needs_approval|scheduled|sending|sent) -> bizim durum. */
export const LINKEDIN_SYNC_INTERVAL_MS = 20 * 60 * 1000; // 20 dk: Buffer yayinlayinca DB'yi SCHEDULED->PUBLISHED cevir
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

/**
 * Bekleyen (QUEUED/SCHEDULED, bufferPostId'li) gonderilerin Buffer'daki GUNCEL durumunu ceker ve DB'yi
 * gunceller. Buffer yayinladiginda (status='sent') kayit PUBLISHED olur. BEST-EFFORT: getBufferPost null
 * donerse o kayda dokunulmaz. Hem admin '/sync' ucu hem worker periyodik olarak bunu cagirir -> panel
 * acilmasa bile durum kendiliginden guncellenir.
 */
export async function syncLinkedinPostStatuses(): Promise<{ checked: number; updated: number }> {
  const pending = await prisma.linkedinPost.findMany({
    where: { status: { in: ['QUEUED', 'SCHEDULED'] }, bufferPostId: { not: null } },
    take: 200,
  });
  let updated = 0;
  for (const p of pending) {
    const remote = await getBufferPost(p.bufferPostId as string);
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
  return { checked: pending.length, updated };
}


const assetUrl = (id: string) => `${config.publicApiUrl.replace(/\/+$/, '')}/linkedin-assets/${id}`;

export async function topUpLinkedinCampaign(): Promise<{ queued: number; remaining: number; capped: boolean }> {
  if (!bufferEnabled()) return { queued: 0, remaining: 0, capped: false };
  let queued = 0, capped = false, remaining = 0;

  for (const p of CAMPAIGN) {
    const marker = p.text.slice(0, 60);
    const done = await prisma.linkedinPost.findFirst({
      where: { content: { startsWith: marker }, status: { in: ['QUEUED', 'SCHEDULED', 'PUBLISHED'] } },
      select: { id: true },
    });
    if (done) continue;
    if (new Date(p.dueAtUtc).getTime() < Date.now()) continue; // tarihi geçmiş — sessizce atla
    remaining++;
    if (capped) continue; // bu turda slot yok; kalanları saymaya devam et

    try {
      let docUrl: string | null = null, docThumb: string | null = null, imgUrl: string | null = null;
      if (p.format === 'pdf' && p.slides) {
        const pdf = await renderCarouselPdf(p.slides as Slide[]);
        const thumb = await renderSlidePng(p.slides[0] as Slide);
        const th = await prisma.linkedinAsset.create({ data: { kind: 'image', mime: 'image/png', title: `${p.mediaTitle} (kapak)`, data: thumb, bytes: thumb.length }, select: { id: true } });
        const a = await prisma.linkedinAsset.create({ data: { kind: 'pdf', mime: 'application/pdf', title: p.mediaTitle!, data: pdf, bytes: pdf.length, pages: p.slides.length, thumbnailId: th.id }, select: { id: true } });
        docUrl = assetUrl(a.id); docThumb = assetUrl(th.id);
      } else if (p.format === 'image' && p.slides) {
        const png = await renderSlidePng(p.slides[0] as Slide);
        const a = await prisma.linkedinAsset.create({ data: { kind: 'image', mime: 'image/png', title: p.mediaTitle!, data: png, bytes: png.length }, select: { id: true } });
        imgUrl = assetUrl(a.id);
      }

      const created = await scheduleLinkedInPost({
        text: p.text, mode: 'customScheduled', dueAt: new Date(p.dueAtUtc).toISOString(),
        imageUrl: imgUrl, documentUrl: docUrl, documentTitle: p.mediaTitle ?? null, documentThumbnailUrl: docThumb,
      });

      // Onceki bekleyen kayit (DRAFT/FAILED) varsa onu guncelle; yoksa yeni satir.
      const prev = await prisma.linkedinPost.findFirst({ where: { content: { startsWith: marker }, status: { in: ['DRAFT', 'FAILED'] } }, select: { id: true } });
      const data = { content: p.text, mediaUrl: docUrl ?? imgUrl, status: 'SCHEDULED', bufferPostId: created.id, scheduledFor: created.dueAt ? new Date(created.dueAt) : new Date(p.dueAtUtc), errorMessage: null };
      if (prev) await prisma.linkedinPost.update({ where: { id: prev.id }, data });
      else await prisma.linkedinPost.create({ data });

      queued++; remaining--;
      console.log(`[linkedin] kampanya kuyruğa alındı: ${p.id} → ${p.localTr} (buffer ${created.id})`);
    } catch (e) {
      const msg = (e as Error).message;
      // Plan siniri: HATA DEGIL, beklenen durum — bir sonraki turda slot acilinca devam eder.
      // Bekleyen gonderi DRAFT olarak TEK satirda tutulur; panelde kirmizi "Basarisiz" kutusuna DUSMEZ.
      if (/scheduled posts limit/i.test(msg)) {
        capped = true;
        const waiting = await prisma.linkedinPost.findFirst({ where: { content: { startsWith: marker }, status: { in: ['DRAFT', 'FAILED'] } }, select: { id: true } });
        const note = 'Buffer plan sınırı (10 zamanlanmış gönderi) dolu — slot açılınca otomatik kuyruğa alınacak.';
        if (waiting) await prisma.linkedinPost.update({ where: { id: waiting.id }, data: { status: 'DRAFT', errorMessage: note, scheduledFor: new Date(p.dueAtUtc) } });
        else await prisma.linkedinPost.create({ data: { content: p.text, status: 'DRAFT', errorMessage: note, scheduledFor: new Date(p.dueAtUtc) } });
        continue;
      }
      console.error(`[linkedin] kampanya kuyruklama hatası (${p.id}): ${msg}`);
    }
  }
  if (queued || remaining) console.log(`[linkedin] kampanya durumu: ${queued} yeni kuyruklandı, ${remaining} sırada${capped ? ' (Buffer plan sınırı dolu — slot açılınca devam edecek)' : ''}.`);
  return { queued, remaining, capped };
}
