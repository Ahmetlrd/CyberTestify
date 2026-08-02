import { prisma } from '../db.js';
import * as pentagi from '../pentagi/client.js';
import { encryptReport, generateReportAccessSecret } from './crypto.js';
import { redactAll } from './piiRedaction.js';
import { FIX_SUGGESTIONS_DELIM } from './scanPackages.js';

type Locale = 'tr' | 'en';

/**
 * Gorev sonuclarindan "cozum onerileri" bolumunu ayirir. Ajan, bulgulari yazdiktan
 * sonra FIX_SUGGESTIONS_DELIM satirini yazip altina duzeltmeleri koyar. Delimiter'in
 * ONCESI bulgu (ana rapor), SONRASI cozum onerisi (ayri/kilitli alan).
 */
function splitFixSuggestions(tasks: pentagi.FlowLogs['tasks']): {
  findingTasks: pentagi.FlowLogs['tasks'];
  fixText: string;
} {
  let fix = '';
  const findingTasks = tasks.map((t) => {
    const r = t.result ?? '';
    const idx = r.indexOf(FIX_SUGGESTIONS_DELIM);
    if (idx === -1) return t;
    fix += r.slice(idx + FIX_SUGGESTIONS_DELIM.length).trim() + '\n\n';
    return { ...t, result: r.slice(0, idx).trim() };
  });
  return { findingTasks, fixText: fix.trim() };
}

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
  const locale: Locale = flow.order.locale === 'en' ? 'en' : 'tr';

  // (3) Cozum onerilerini bulgulardan AYIR (ayni akista uretildi, ekstra maliyet yok).
  const { findingTasks, fixText } = splitFixSuggestions(logs.tasks);

  // KENDI TARAFIMIZDA veri minimizasyonu: bulgu kaniti (evidence) olarak sunulan
  // ham veride sizmis yapisal kisisel veriyi (email/telefon/TCKN/kart/IBAN)
  // sifreli DB'mize yazmadan ONCE maskele. Musteri "su endpoint'te veri sizintisi
  // var" bulgusunu gorur ama sizan ham PII bizde tam haliyle SAKLANMAZ. (Ayni
  // mantik PentAGI Go tarafinda veri Anthropic'e gitmeden de uygulanir — PATCHES.md.)
  const markdown = redactAll(
    renderReportMarkdown(flow.order.domain.hostname, flow.order.package.displayName, { ...logs, tasks: findingTasks }, locale),
  );
  // EKSIK RAPOR TESPITI: tarama erken durdurulduysa/coktuyse rapor bos/eksik olur.
  // Sonucu (result) dolu en az bir gorev yoksa raporu "eksik" isaretle → musteriye
  // panelde acik uyari gosterilir (kimse "raporunuz hazir" deyip bos rapor almasin).
  const completedTasks = findingTasks.filter((t) => (t.result ?? '').trim().length > 0);
  const incomplete = completedTasks.length === 0;
  const incompleteReason = incomplete
    ? 'Tarama tamamlanamadan sonlandi (erken durdurma veya bir hata olabilir); rapor eksik.'
    : null;

  const accessSecret = generateReportAccessSecret();
  const base = encryptReport(Buffer.from(markdown, 'utf-8'), accessSecret);

  // (3) Cozum onerileri varsa AYNI accessSecret ile AYRI sifrele (kilitli alan).
  let fixFields: Record<string, Buffer> = {};
  if (fixText.trim().length > 0) {
    const fixMd = redactAll(renderFixSuggestionsMarkdown(flow.order.domain.hostname, fixText, locale));
    const enc = encryptReport(Buffer.from(fixMd, 'utf-8'), accessSecret);
    fixFields = {
      fixSuggestions: enc.encryptedBlob,
      fixSuggestionsIv: enc.iv,
      fixSuggestionsAuthTag: enc.authTag,
      fixSuggestionsSalt: enc.keyDerivationSalt,
    };
  }

  await prisma.report.create({
    data: {
      orderId: flow.orderId,
      encryptedBlob: base.encryptedBlob,
      iv: base.iv,
      authTag: base.authTag,
      keyDerivationSalt: base.keyDerivationSalt,
      incomplete,
      incompleteReason,
      ...fixFields,
    },
  });

  await prisma.order.update({ where: { id: flow.orderId }, data: { status: 'scan_completed' } });

  // Ham veriyi PentAGI tarafinda tutmuyoruz — rapor uretildikten hemen
  // sonra siliniyor (bkz konusmadaki "ham logu kisa surede sil" prensibi).
  await pentagi.purgeFlowRawData(flow.pentagiFlowId);
  await prisma.flow.update({ where: { id: flow.id }, data: { rawDataPurgedAt: new Date() } });

  return { accessSecret };
}

const T = {
  tr: {
    title: 'Guvenlik Tarama Raporu', target: 'Hedef', pkg: 'Paket', created: 'Olusturma tarihi',
    findings: 'Bulgular', noResult: '_(sonuc yok)_', noFindings: '_Bu taramada raporlanacak gorev bulunamadi._',
    status: 'Durum', screenshots: 'Ekran Goruntuleri', none: '_Yok_', legalTitle: 'Yasal Uyari ve Kapsam',
    legal: [
      '**Yapay zeka uretimi:** Bu rapor yapay zeka tabanli otomatik bir ajan tarafindan uretilmistir; olgusal ifadeler bagimsiz dogrulanmadan kullanilmamalidir.',
      '**Kapsam:** Tarama YALNIZCA sahipligi dogrulanmis hedefle ve **pasif** yontemlerle sinirlidir; ic ag, kimlik dogrulamali test ve sizma testi KAPSAM DISIDIR.',
      '**Resmi degildir:** Bu rapor resmi uyumluluk denetimi/sertifikasyon (ASV/QSA vb.) yerine gecmez.',
      '**Sorumluluk:** Bulgularin dogrulanmasi ve giderilmesi musterinin sorumlulugundadir.',
    ],
    fixTitle: 'AI Cozum Onerileri', fixNote: 'Bu bolum duzeltme (remediation) icindir; istismar/exploit kodu icermez.',
  },
  en: {
    title: 'Security Scan Report', target: 'Target', pkg: 'Package', created: 'Generated at',
    findings: 'Findings', noResult: '_(no result)_', noFindings: '_No reportable task was produced in this scan._',
    status: 'Status', screenshots: 'Screenshots', none: '_None_', legalTitle: 'Legal Notice & Scope',
    legal: [
      '**AI-generated:** This report was produced by an autonomous AI agent; factual statements must be independently verified before acting on them.',
      '**Scope:** The scan is limited to the ownership-verified target and **passive** methods only; internal network, authenticated testing and penetration testing are OUT OF SCOPE.',
      '**Not official:** This report is not a substitute for an official compliance audit/certification (ASV/QSA, etc.).',
      '**Responsibility:** Verifying and remediating findings is the customer’s responsibility.',
    ],
    fixTitle: 'AI Fix Suggestions', fixNote: 'This section is remediation guidance only; it contains no exploit code.',
  },
} as const;

export function renderReportMarkdown(hostname: string, packageName: string, logs: pentagi.FlowLogs, locale: Locale = 'tr'): string {
  const t = T[locale];
  const findings = logs.tasks
    .map((x) => `### ${x.title}\n\n**${t.status}:** ${x.status}\n\n${x.result ?? t.noResult}`)
    .join('\n\n---\n\n');

  return `# ${t.title}

**${t.target}:** ${hostname}
**${t.pkg}:** ${packageName}
**${t.created}:** ${new Date().toISOString()}

---

## ${t.findings}

${findings || t.noFindings}

---

## ${t.screenshots}

${logs.screenshots.map((s) => `- ${s.name}: ${s.url}`).join('\n') || t.none}

---

## ${t.legalTitle}

${t.legal.map((l) => `- ${l}`).join('\n')}
`;
}

// (3) Cozum onerileri bolumu — ayri/kilitli alanda saklanir, odeme sonrasi acilir.
export function renderFixSuggestionsMarkdown(hostname: string, fixText: string, locale: Locale = 'tr'): string {
  const t = T[locale];
  return `# ${t.fixTitle} — ${hostname}\n\n> ${t.fixNote}\n\n${fixText}\n`;
}
