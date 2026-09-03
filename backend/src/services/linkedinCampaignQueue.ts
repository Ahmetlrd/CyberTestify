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
import { scheduleLinkedInPost, bufferEnabled } from './bufferClient.js';
import { config } from '../config.js';

export const CAMPAIGN_TOPUP_INTERVAL_MS = 6 * 60 * 60 * 1000; // 6 saatte bir dener (gün içi slot açılırsa yakalar)

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

      // Onceki FAILED kaydi varsa onu guncelle; yoksa yeni satir.
      const prev = await prisma.linkedinPost.findFirst({ where: { content: { startsWith: marker }, status: 'FAILED' }, select: { id: true } });
      const data = { content: p.text, mediaUrl: docUrl ?? imgUrl, status: 'SCHEDULED', bufferPostId: created.id, scheduledFor: created.dueAt ? new Date(created.dueAt) : new Date(p.dueAtUtc), errorMessage: null };
      if (prev) await prisma.linkedinPost.update({ where: { id: prev.id }, data });
      else await prisma.linkedinPost.create({ data });

      queued++; remaining--;
      console.log(`[linkedin] kampanya kuyruğa alındı: ${p.id} → ${p.localTr} (buffer ${created.id})`);
    } catch (e) {
      const msg = (e as Error).message;
      // Plan siniri: HATA DEGIL, beklenen durum — bir sonraki turda slot acilinca devam eder.
      if (/scheduled posts limit/i.test(msg)) { capped = true; continue; }
      console.error(`[linkedin] kampanya kuyruklama hatası (${p.id}): ${msg}`);
    }
  }
  if (queued || remaining) console.log(`[linkedin] kampanya durumu: ${queued} yeni kuyruklandı, ${remaining} sırada${capped ? ' (Buffer plan sınırı dolu — slot açılınca devam edecek)' : ''}.`);
  return { queued, remaining, capped };
}
