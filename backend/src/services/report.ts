import { prisma } from '../db.js';
import * as pentagi from '../pentagi/client.js';
import { encryptReport, generateReportAccessSecret } from './crypto.js';
import { redactAll } from './piiRedaction.js';

/**
 * Flow tamamlandiginda cagrilir (worker.ts). Ham loglari PentAGI'den ceker,
 * okunabilir bir Markdown rapor haline getirir, musteriye ozel bir erisim
 * sifresiyle sifreler ve PentAGI tarafindaki ham veriyi siler.
 *
 * DONUS DEGERI icindeki accessSecret SADECE BURADA, bir kereligine
 * gorunur — cagiran kod (worker.ts) bunu veritabanina YAZMADAN dogrudan
 * musteriye e-posta ile gondermeli (rapor indirme linkinden ayri bir kanal).
 */
export async function generateAndStoreReport(flowId: string) {
  const flow = await prisma.flow.findUniqueOrThrow({
    where: { id: flowId },
    include: { order: { include: { domain: true, package: true } } },
  });

  const logs = await pentagi.getFlowLogs(flow.pentagiFlowId);

  // KENDI TARAFIMIZDA veri minimizasyonu: bulgu kaniti (evidence) olarak sunulan
  // ham veride sizmis yapisal kisisel veriyi (email/telefon/TCKN/kart/IBAN)
  // sifreli DB'mize yazmadan ONCE maskele. Musteri "su endpoint'te veri sizintisi
  // var" bulgusunu gorur ama sizan ham PII bizde tam haliyle SAKLANMAZ. (Ayni
  // mantik PentAGI Go tarafinda veri Anthropic'e gitmeden de uygulanir — PATCHES.md.)
  const markdown = redactAll(
    renderReportMarkdown(flow.order.domain.hostname, flow.order.package.displayName, logs),
  );
  const accessSecret = generateReportAccessSecret();
  const { encryptedBlob, iv, authTag, keyDerivationSalt } = encryptReport(
    Buffer.from(markdown, 'utf-8'),
    accessSecret,
  );

  await prisma.report.create({
    data: {
      orderId: flow.orderId,
      encryptedBlob,
      iv,
      authTag,
      keyDerivationSalt,
    },
  });

  await prisma.order.update({ where: { id: flow.orderId }, data: { status: 'scan_completed' } });

  // Ham veriyi PentAGI tarafinda tutmuyoruz — rapor uretildikten hemen
  // sonra siliniyor (bkz konusmadaki "ham logu kisa surede sil" prensibi).
  await pentagi.purgeFlowRawData(flow.pentagiFlowId);
  await prisma.flow.update({ where: { id: flow.id }, data: { rawDataPurgedAt: new Date() } });

  return { accessSecret };
}

export function renderReportMarkdown(hostname: string, packageName: string, logs: pentagi.FlowLogs): string {
  const findings = logs.tasks
    .map((t) => `### ${t.title}\n\n**Durum:** ${t.status}\n\n${t.result ?? '_(sonuc yok)_'}`)
    .join('\n\n---\n\n');

  return `# Guvenlik Tarama Raporu

**Hedef:** ${hostname}
**Paket:** ${packageName}
**Olusturma tarihi:** ${new Date().toISOString()}

---

## Bulgular

${findings || '_Bu taramada raporlanacak gorev bulunamadi._'}

---

## Ekran Goruntuleri

${logs.screenshots.map((s) => `- ${s.name}: ${s.url}`).join('\n') || '_Yok_'}

---

## Yasal Uyari ve Kapsam

- **Yapay zeka uretimi:** Bu rapor, yapay zeka tabanli otomatik bir ajan (AI)
  tarafindan uretilmistir. Icerdigi tespit ve degerlendirmeler yardimci
  niteliktedir; **olgusal ifadeler bagimsiz olarak dogrulanmadan karar alinarak
  kullanilmamalidir.**
- **Kapsam:** Tarama YALNIZCA sahipligi/yetkisi dogrulanmis \`${hostname}\` hedefiyle
  ve **pasif (saldirgan olmayan)** yontemlerle sinirlidir. Ic ag, segmentasyon,
  kimlik dogrulamali test ve sizma testi (pentest) KAPSAM DISIDIR.
- **Resmi degildir:** Bu rapor resmi bir uyumluluk denetimi, sertifikasyon veya
  akredite sizma testi (ASV/QSA vb.) yerine gecmez.
- **Sorumluluk:** Bulgularin dogrulanmasi ve giderilmesi musterinin
  sorumlulugundadir. Kritik kararlar oncesi nitelikli bir uzman incelemesi
  onerilir.
`;
}
