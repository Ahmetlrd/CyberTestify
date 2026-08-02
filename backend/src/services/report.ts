import { prisma } from '../db.js';
import * as pentagi from '../pentagi/client.js';
import { encryptReport, generateReportAccessSecret } from './crypto.js';
import { redactAll } from './piiRedaction.js';
import { FIX_SUGGESTIONS_DELIM } from './scanPackages.js';

type Locale = 'tr' | 'en';

/**
 * Ajanin GERCEK bulgularini (tamamlama raporlarini) toplar.
 *
 * KOK DUZELTME (2026-08-02): PentAGI veri modelinde bir gorev/alt-gorev icin ATAMA
 * (talimat) ile TAMAMLAMA (sonuc raporu) AYRI kolonlarda tutulur:
 *   - Task.input / Subtask.description / MessageLog.message  -> ATAMA (talimat)  [KULLANMA]
 *   - Task.result / Subtask.result / MessageLog.result       -> TAMAMLAMA (rapor) [KULLAN]
 * Bir `report`-tipi MessageLog'ta bile `message`=atama, `result`=tamamlamadir.
 * Eski kod tavana carpan (Task.result bos) taramalarda `messageLogs.message`'e
 * dusuyor, yani ajanin gercek son ciktisi yerine ona verilen GOREV TALIMATINI
 * rapora yaziyordu (iso27001/kvkk/header_leak'te ayni sistemik hata). Artik yalniz
 * `result` (tamamlama) alanlarini okuyoruz; uzunluk/sezgi tahmini YOK, resmi alan ayrimi.
 *
 * Oncelik: (1) task-seviyesi sentez (Task.result) — dogal bitiste dolu; yoksa
 * (2) TUM alt-gorev tamamlamalari (Subtask.result) birlestirilir — tavana carpsa
 * bile dolu; yoksa (3) report-tipi MessageLog'larin `result`'i; yoksa (4) done'in
 * `result`'i. Hicbir asamada ATAMA metni (message/description) bulgu sayilmaz.
 */
function collectFindings(logs: pentagi.FlowLogs): string {
  const join = (parts: string[]) => parts.filter((p) => p.trim().length > 0).join('\n\n---\n\n').trim();

  // (1) Task-seviyesi tamamlama sentezi (dogal bitiste PentAGI reporter'i doldurur).
  const taskText = join(
    logs.tasks
      .filter((t) => (t.result ?? '').trim().length > 0)
      .map((t) => `### ${t.title}\n\n${(t.result ?? '').trim()}`),
  );
  if (taskText) return taskText;

  // (2) TUM alt-gorev TAMAMLAMALARI (Subtask.result). Tavana carpan taramada Task.result
  //     bos olsa da alt-gorevler kendi sonuclarini yazmis olur — hepsini birlestir.
  const subtaskText = join(
    logs.tasks
      .flatMap((t) => t.subtasks ?? [])
      .filter((st) => (st.result ?? '').trim().length > 0)
      .map((st) => `### ${st.title}\n\n${(st.result ?? '').trim()}`),
  );
  if (subtaskText) return subtaskText;

  // (3) report-tipi MessageLog'larin TAMAMLAMASI (message DEGIL, result).
  const reportText = join(
    logs.messageLogs.filter((m) => m.type === 'report').map((m) => (m.result ?? '').trim()),
  );
  if (reportText) return reportText;

  // (4) Son care: done-tipi MessageLog'un result'i (yoksa message'a dusme — atama olabilir).
  return join(logs.messageLogs.filter((m) => m.type === 'done').map((m) => (m.result ?? '').trim()));
}

/** Bulgulardan "cozum onerileri" bolumunu (delimiter sonrasi) ayirir. */
function splitFixSuggestions(text: string): { findings: string; fixText: string } {
  const idx = text.indexOf(FIX_SUGGESTIONS_DELIM);
  if (idx === -1) return { findings: text.trim(), fixText: '' };
  return {
    findings: text.slice(0, idx).trim(),
    fixText: text.slice(idx + FIX_SUGGESTIONS_DELIM.length).trim(),
  };
}

/**
 * Flow tamamlandiginda cagrilir (worker.ts). Ham loglari PentAGI'den ceker,
 * okunabilir bir Markdown rapor haline getirir, musteriye ozel bir erisim
 * sifresiyle sifreler ve PentAGI tarafindaki ham veriyi siler.
 */
export async function generateAndStoreReport(flowId: string) {
  const flow = await prisma.flow.findUniqueOrThrow({
    where: { id: flowId },
    include: { order: { include: { domain: true, package: true } } },
  });

  const logs = await pentagi.getFlowLogs(flow.pentagiFlowId);
  const locale: Locale = flow.order.locale === 'en' ? 'en' : 'tr';

  // (3) Cozum onerilerini bulgulardan AYIR (ayni akista uretildi, ekstra maliyet yok).
  const { findings, fixText } = splitFixSuggestions(collectFindings(logs));

  // EKSIK RAPOR TESPITI: hicbir kaynakta (task.result / report / done) icerik yoksa
  // rapor gercekten bostur → "eksik" isaretle (musteriye acik uyari gosterilir).
  const incomplete = findings.trim().length === 0;
  const incompleteReason = incomplete
    ? 'Tarama tamamlanamadan sonlandi (erken durdurma veya bir hata olabilir); rapor eksik.'
    : null;

  // KENDI TARAFIMIZDA veri minimizasyonu: sizmis yapisal PII'yi (email/telefon/
  // TCKN/kart/IBAN) sifreli DB'ye yazmadan ONCE maskele (ayni mantik PentAGI Go
  // tarafinda Anthropic'e gitmeden de uygulanir — PATCHES.md).
  const markdown = redactAll(
    renderReportMarkdown(flow.order.domain.hostname, flow.order.package.displayName, findings, logs.screenshots, locale),
  );

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

  // Ham veriyi PentAGI tarafinda tutmuyoruz — rapor uretildikten hemen sonra sil.
  await pentagi.purgeFlowRawData(flow.pentagiFlowId);
  await prisma.flow.update({ where: { id: flow.id }, data: { rawDataPurgedAt: new Date() } });

  return { accessSecret };
}

const T = {
  tr: {
    title: 'Guvenlik Tarama Raporu', target: 'Hedef', pkg: 'Paket', created: 'Olusturma tarihi',
    findings: 'Bulgular', noFindings: '_Bu taramada raporlanacak bulgu uretilemedi._',
    screenshots: 'Ekran Goruntuleri', none: '_Yok_', legalTitle: 'Yasal Uyari ve Kapsam',
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
    findings: 'Findings', noFindings: '_No reportable findings could be produced in this scan._',
    screenshots: 'Screenshots', none: '_None_', legalTitle: 'Legal Notice & Scope',
    legal: [
      '**AI-generated:** This report was produced by an autonomous AI agent; factual statements must be independently verified before acting on them.',
      '**Scope:** The scan is limited to the ownership-verified target and **passive** methods only; internal network, authenticated testing and penetration testing are OUT OF SCOPE.',
      '**Not official:** This report is not a substitute for an official compliance audit/certification (ASV/QSA, etc.).',
      '**Responsibility:** Verifying and remediating findings is the customer’s responsibility.',
    ],
    fixTitle: 'AI Fix Suggestions', fixNote: 'This section is remediation guidance only; it contains no exploit code.',
  },
} as const;

export function renderReportMarkdown(
  hostname: string,
  packageName: string,
  findingsMd: string,
  screenshots: pentagi.FlowLogs['screenshots'],
  locale: Locale = 'tr',
): string {
  const t = T[locale];
  return `# ${t.title}

**${t.target}:** ${hostname}
**${t.pkg}:** ${packageName}
**${t.created}:** ${new Date().toISOString()}

---

## ${t.findings}

${findingsMd.trim() || t.noFindings}

---

## ${t.screenshots}

${screenshots.map((s) => `- ${s.name}: ${s.url}`).join('\n') || t.none}

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
