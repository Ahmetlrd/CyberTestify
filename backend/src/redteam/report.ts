/**
 * (OTONOM AI RED TEAM — 3b-ii) DETERMİNİSTİK RAPOR RENDER.
 * Girdi = binder.py'nin JSON çıktısı (ham artefakta bağlı 3-katman). Bu modül LLM KULLANMAZ;
 * yalnız binder'ın deterministik çıktısını dürüst bir rapora çevirir. İlkeler:
 *  - Yalnız KANITLI bulgular "bulgu" olarak sunulur (ham kanıt referansıyla).
 *  - BELİRSİZ bulgular "inceleme gerektiren" katmanında AÇIKÇA gösterilir — gizlice silinmez.
 *  - HAYALET bulgular yalnız SAYI olarak şeffaflık için not edilir (rapora alınmaz).
 *  - Genel risk = KANITLI bulguların en yükseği; asla belirsiz/hayalet ile şişirilmez.
 *  - Dürüst dil + deterministik-değil disclaimer. Resmi denetim/sertifikasyon DEĞİL.
 * 6 paketin deterministik rapor motoruna DOKUNMAZ (ayrı modül).
 */

export type BinderEvidence = { artifactRef: string; signature: string; detail: string };
export type BinderFinding = {
  title: string;
  category: string;
  endpoint: string;
  severity: 'kritik' | 'yüksek' | 'orta' | 'düşük';
  tier: 'KANITLI' | 'BELIRSIZ' | 'HAYALET';
  evidence: BinderEvidence | null;
  reason: string;
};
export type BinderOutput = {
  meta?: Record<string, unknown>;
  artifactCount: number;
  claimCount: number;
  summary: { kanitli: number; belirsiz: number; hayalet: number };
  overallRisk: 'kritik' | 'yüksek' | 'orta' | 'düşük' | 'temiz';
  findings: BinderFinding[];
};

export type RedTeamReportMeta = {
  target: string;
  level: 'S1' | 'S2' | 'S3';
  environment: 'test' | 'staging' | 'prod';
  generatedAt: string; // ISO — çağıran verir (deterministik render; modül saat okumaz)
  costUsd?: number | null;
  llmCalls?: number | null;
};

export type RedTeamReport = {
  meta: RedTeamReportMeta;
  overallRisk: BinderOutput['overallRisk'];
  counts: BinderOutput['summary'] & { artifacts: number };
  proven: BinderFinding[];      // KANITLI
  needsReview: BinderFinding[]; // BELİRSİZ
  eliminated: number;           // HAYALET (yalnız sayı)
  disclaimer: string;
};

const RISK_LABEL: Record<string, string> = {
  kritik: 'Kritik', yüksek: 'Yüksek', orta: 'Orta', düşük: 'Düşük', temiz: 'Temiz',
};

const DISCLAIMER =
  'Bu rapor DENEYSEL otonom red-team katmanı tarafından üretilmiştir. Sonuçlar DETERMİNİSTİK ' +
  'DEĞİLDİR (aynı hedefte tekrar farklı sonuç verebilir) ve resmi bir denetim, sızma testi ' +
  'sertifikasyonu ya da uygunluk belgesi DEĞİLDİR. Her "kanıtlı" bulgu, ajanın sözüne değil, ' +
  'saklanan HAM kanıta (gerçek istek/yanıt, terminal çıktısı) bağlıdır. "İnceleme gerektiren" ' +
  'bulgular silinmemiş, insan doğrulamasına bırakılmıştır.';

/** Binder JSON + koşu meta → yapısal rapor (saf/deterministik). */
export function buildRedTeamReport(binder: BinderOutput, meta: RedTeamReportMeta): RedTeamReport {
  const proven = binder.findings.filter((f) => f.tier === 'KANITLI');
  const needsReview = binder.findings.filter((f) => f.tier === 'BELIRSIZ');
  const eliminated = binder.findings.filter((f) => f.tier === 'HAYALET').length;
  return {
    meta,
    overallRisk: binder.overallRisk, // yalnız KANITLI'dan (binder hesaplar); burada da şişirmeyiz
    counts: { ...binder.summary, artifacts: binder.artifactCount },
    proven,
    needsReview,
    eliminated,
    disclaimer: DISCLAIMER,
  };
}

function fmtFinding(f: BinderFinding): string {
  const ev = f.evidence
    ? `\n    - Ham kanıt: \`${f.evidence.artifactRef}\`${f.evidence.signature ? ` — imza: \`${f.evidence.signature}\`` : ''}\n    - ${f.evidence.detail}`
    : '';
  return `- **${f.title}** — ${f.category} · şiddet: ${RISK_LABEL[f.severity] ?? f.severity}${f.endpoint ? ` · \`${f.endpoint}\`` : ''}${ev}`;
}

/** Yapısal rapor → Markdown (deterministik, dürüst). */
export function renderRedTeamMarkdown(r: RedTeamReport): string {
  const L: string[] = [];
  L.push(`# Otonom AI Red Team — Bulgu Raporu`);
  L.push('');
  L.push(`> ${r.disclaimer}`);
  L.push('');
  L.push(`**Hedef:** ${r.meta.target}  ·  **Seviye:** ${r.meta.level}  ·  **Ortam:** ${r.meta.environment}  ·  **Tarih:** ${r.meta.generatedAt}`);
  L.push('');
  L.push(`**Genel risk:** ${RISK_LABEL[r.overallRisk] ?? r.overallRisk} _(yalnız kanıtlı bulgulardan; belirsiz/elenen ile şişirilmez)_`);
  L.push(`**Özet:** kanıtlı ${r.counts.kanitli} · inceleme gerektiren ${r.counts.belirsiz} · elenen ${r.eliminated} · ham artefakt ${r.counts.artifacts}`);
  if (r.meta.costUsd != null || r.meta.llmCalls != null) {
    L.push(`**Koşu:** ${r.meta.llmCalls ?? '?'} LLM çağrısı · ~$${(r.meta.costUsd ?? 0).toFixed(4)}`);
  }
  L.push('');
  L.push(`## Kanıtlı bulgular (${r.proven.length})`);
  L.push(r.proven.length ? r.proven.map(fmtFinding).join('\n') : '_Kanıtlı bulgu yok._');
  L.push('');
  L.push(`## İnceleme gerektiren — belirsiz (${r.needsReview.length})`);
  L.push('_Bunlar ham artefaktı olan ama kesin deterministik imzası olmayan iddialardır. Silinmemiştir; insan doğrulaması önerilir._');
  L.push('');
  L.push(r.needsReview.length ? r.needsReview.map(fmtFinding).join('\n') : '_Belirsiz bulgu yok._');
  L.push('');
  L.push(`## Elenen (hayalet): ${r.eliminated}`);
  L.push('_Ajanın iddia ettiği ama hiçbir ham kanıtı bulunmayan bulgular elendi ve rapora ALINMADI._');
  return L.join('\n');
}

/** Yapısal rapor → basit, gömülü-stilli HTML (panelde göstermek için; harici kaynak yok). */
export function renderRedTeamHtml(r: RedTeamReport): string {
  const esc = (s: string) => s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]!));
  const findingLi = (f: BinderFinding) =>
    `<li><b>${esc(f.title)}</b> — ${esc(f.category)} · ${esc(RISK_LABEL[f.severity] ?? f.severity)}${
      f.endpoint ? ` · <code>${esc(f.endpoint)}</code>` : ''
    }${
      f.evidence
        ? `<div class="ev">Ham kanıt: <code>${esc(f.evidence.artifactRef)}</code>${
            f.evidence.signature ? ` · imza: <code>${esc(f.evidence.signature)}</code>` : ''
          }<br>${esc(f.evidence.detail)}</div>`
        : ''
    }</li>`;
  return `<section class="rt-report">
  <p class="rt-disc">${esc(r.disclaimer)}</p>
  <p><b>Hedef:</b> ${esc(r.meta.target)} · <b>Seviye:</b> ${esc(r.meta.level)} · <b>Ortam:</b> ${esc(r.meta.environment)} · <b>Tarih:</b> ${esc(r.meta.generatedAt)}</p>
  <p><b>Genel risk:</b> ${esc(RISK_LABEL[r.overallRisk] ?? r.overallRisk)} <small>(yalnız kanıtlı bulgulardan)</small></p>
  <p><b>Özet:</b> kanıtlı ${r.counts.kanitli} · inceleme gerektiren ${r.counts.belirsiz} · elenen ${r.eliminated} · ham artefakt ${r.counts.artifacts}</p>
  <h3>Kanıtlı bulgular (${r.proven.length})</h3>
  <ul>${r.proven.map(findingLi).join('') || '<li><i>Kanıtlı bulgu yok.</i></li>'}</ul>
  <h3>İnceleme gerektiren — belirsiz (${r.needsReview.length})</h3>
  <p><small>Ham artefaktı olan ama kesin imzası olmayan iddialar; silinmedi, insan doğrulaması önerilir.</small></p>
  <ul>${r.needsReview.map(findingLi).join('') || '<li><i>Belirsiz bulgu yok.</i></li>'}</ul>
  <h3>Elenen (hayalet): ${r.eliminated}</h3>
  <p><small>Ajanın iddia ettiği ama ham kanıtı olmayan bulgular elendi, rapora alınmadı.</small></p>
</section>`;
}
