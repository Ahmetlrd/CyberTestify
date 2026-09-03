/**
 * (KAMPANYA KUYRUKLAMA) campaigns/linkedin2026_09.ts icindeki gonderileri:
 *   1) PDF carousel / gorsel medyalarini SUNUCUDA uretir (puppeteer-core) ve DB'ye yazar,
 *   2) PUBLIC /linkedin-assets/:id URL'ini Buffer'a vererek gonderiyi ZAMANLAR,
 *   3) LinkedinPost kaydini SCHEDULED olarak isaretler.
 *
 * IDEMPOTENT: ayni id'li gonderi zaten SCHEDULED/PUBLISHED ise ATLANIR — betik guvenle
 * tekrar calistirilabilir (kismi hata sonrasi kaldigi yerden devam eder).
 *
 * KURU CALISMA:  npx tsx src/scripts/queueLinkedinCampaign.ts --dry
 * GERCEK:        npx tsx src/scripts/queueLinkedinCampaign.ts
 */
import { prisma } from '../db.js';
import { CAMPAIGN } from '../campaigns/linkedin2026_09.js';
import { renderCarouselPdf, renderSlidePng, type Slide } from '../services/linkedinCarousel.js';
import { scheduleLinkedInPost, resolveLinkedInTarget } from '../services/bufferClient.js';
import { config } from '../config.js';

const DRY = process.argv.includes('--dry');
const assetUrl = (id: string) => `${config.publicApiUrl.replace(/\/+$/, '')}/linkedin-assets/${id}`;

async function main() {
  const target = await resolveLinkedInTarget();
  console.log(`Kanal: ${target.channelName} (${target.channelId})`);
  console.log(`Mod: ${DRY ? 'KURU ÇALIŞMA (hiçbir şey gönderilmez)' : 'GERÇEK'}\n`);

  let queued = 0, skipped = 0;
  for (const p of CAMPAIGN) {
    // Idempotency: metnin ilk 60 karakteri + tarih ile eslesen aktif kayit var mi?
    const marker = p.text.slice(0, 60);
    const existing = await prisma.linkedinPost.findFirst({
      where: { content: { startsWith: marker }, status: { in: ['QUEUED', 'SCHEDULED', 'PUBLISHED'] } },
      select: { id: true, status: true },
    });
    if (existing) { console.log(`⏭  ${p.id} — zaten ${existing.status}, atlandı`); skipped++; continue; }

    const when = new Date(p.dueAtUtc);
    if (when.getTime() < Date.now()) { console.log(`⏭  ${p.id} — tarih geçmiş (${p.localTr}), atlandı`); skipped++; continue; }

    let docUrl: string | null = null, docThumb: string | null = null, imgUrl: string | null = null, mediaNote = 'metin';
    if (!DRY && p.format === 'pdf' && p.slides) {
      const pdf = await renderCarouselPdf(p.slides as Slide[]);
      const thumb = await renderSlidePng(p.slides[0] as Slide);
      const th = await prisma.linkedinAsset.create({ data: { kind: 'image', mime: 'image/png', title: `${p.mediaTitle} (kapak)`, data: thumb, bytes: thumb.length }, select: { id: true } });
      const a = await prisma.linkedinAsset.create({ data: { kind: 'pdf', mime: 'application/pdf', title: p.mediaTitle!, data: pdf, bytes: pdf.length, pages: p.slides.length, thumbnailId: th.id }, select: { id: true } });
      docUrl = assetUrl(a.id); docThumb = assetUrl(th.id);
      mediaNote = `PDF ${p.slides.length} sayfa · ${(pdf.length / 1024).toFixed(0)} KB`;
    } else if (!DRY && p.format === 'image' && p.slides) {
      const png = await renderSlidePng(p.slides[0] as Slide);
      const a = await prisma.linkedinAsset.create({ data: { kind: 'image', mime: 'image/png', title: p.mediaTitle!, data: png, bytes: png.length }, select: { id: true } });
      imgUrl = assetUrl(a.id);
      mediaNote = `PNG · ${(png.length / 1024).toFixed(0)} KB`;
    } else if (DRY) {
      mediaNote = p.format === 'pdf' ? `PDF ${p.slides?.length ?? 0} sayfa (üretilmedi)` : p.format === 'image' ? 'PNG (üretilmedi)' : 'metin';
    }

    if (DRY) { console.log(`○  ${p.id.padEnd(26)} ${p.localTr}  ${p.format.padEnd(5)} ${mediaNote}`); queued++; continue; }

    const row = await prisma.linkedinPost.create({ data: { content: p.text, mediaUrl: docUrl ?? imgUrl, status: 'DRAFT', scheduledFor: when } });
    try {
      const created = await scheduleLinkedInPost({
        text: p.text, mode: 'customScheduled', dueAt: when.toISOString(),
        imageUrl: imgUrl, documentUrl: docUrl, documentTitle: p.mediaTitle ?? null, documentThumbnailUrl: docThumb,
      });
      await prisma.linkedinPost.update({ where: { id: row.id }, data: { status: 'SCHEDULED', bufferPostId: created.id, scheduledFor: created.dueAt ? new Date(created.dueAt) : when, errorMessage: null } });
      console.log(`✓  ${p.id.padEnd(26)} ${p.localTr}  ${p.format.padEnd(5)} ${mediaNote}  → buffer ${created.id}`);
      queued++;
    } catch (e) {
      await prisma.linkedinPost.update({ where: { id: row.id }, data: { status: 'FAILED', errorMessage: (e as Error).message } });
      console.log(`✗  ${p.id} — HATA: ${(e as Error).message}`);
    }
  }
  console.log(`\nToplam: ${queued} kuyruklandı, ${skipped} atlandı, ${CAMPAIGN.length} gönderi tanımlı.`);
}
main().then(() => process.exit(0)).catch((e) => { console.error('HATA:', e.message); process.exit(1); });
