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

/** Yapısal rapor → TAM, kendi-kendine yeten HTML DOKÜMANI (panelde "Raporu Gör" + PDF için). */
export function renderRedTeamFullHtml(r: RedTeamReport): string {
  const esc = (s: string) => String(s ?? '').replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]!));
  const riskColor: Record<string, string> = { kritik: '#b91c1c', yüksek: '#c2410c', orta: '#a16207', düşük: '#15803d', temiz: '#15803d' };
  const rc = riskColor[r.overallRisk] ?? '#334155';
  const finding = (f: BinderFinding, tierColor: string) => `
    <li style="margin:0 0 12px;padding:10px 12px;border-left:4px solid ${tierColor};background:#f8fafc;border-radius:0 8px 8px 0;">
      <div style="font-weight:700;color:#0f172a;">${esc(f.title)}</div>
      <div style="font-size:12px;color:#64748b;margin-top:2px;">${esc(f.category)} · şiddet: ${esc(RISK_LABEL[f.severity] ?? f.severity)}${f.endpoint ? ` · <code>${esc(f.endpoint)}</code>` : ''}</div>
      ${f.evidence ? `<div style="font-size:12px;color:#334155;margin-top:6px;padding:6px 8px;background:#eef2ff;border-radius:6px;">
        <b>Ham kanıt:</b> <code>${esc(f.evidence.artifactRef)}</code>${f.evidence.signature ? ` · imza: <code>${esc(f.evidence.signature)}</code>` : ''}<br>${esc(f.evidence.detail)}</div>` : ''}
      <div style="font-size:11px;color:#94a3b8;margin-top:4px;">${esc(f.reason)}</div>
    </li>`;
  return `<!doctype html><html lang="tr"><head><meta charset="utf-8"><title>Otonom AI Red Team — Bulgu Raporu</title>
<style>
  *{box-sizing:border-box} body{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#0f172a;margin:0;padding:28px 32px;line-height:1.5;}
  h1{font-size:22px;margin:0 0 4px} h2{font-size:15px;margin:22px 0 8px;color:#1e293b;border-bottom:1px solid #e2e8f0;padding-bottom:4px}
  .disc{background:#fff7ed;border:1px solid #fdba74;border-radius:8px;padding:12px 14px;font-size:12px;color:#7c2d12;margin:12px 0 18px}
  .meta{font-size:13px;color:#475569} .risk{display:inline-block;padding:3px 12px;border-radius:999px;color:#fff;font-weight:700;background:${rc}}
  ul{list-style:none;padding:0;margin:0} code{background:#e2e8f0;padding:1px 4px;border-radius:4px;font-size:11px}
  .sum{display:flex;gap:16px;flex-wrap:wrap;font-size:13px;margin:8px 0}
  .sum b{font-size:18px;display:block}
</style></head><body>
  <h1>Otonom AI Red Team — Bulgu Raporu</h1>
  <div class="meta"><b>Hedef:</b> ${esc(r.meta.target)} · <b>Seviye:</b> ${esc(r.meta.level)} · <b>Ortam:</b> ${esc(r.meta.environment)} · <b>Tarih:</b> ${esc(r.meta.generatedAt)}${r.meta.costUsd != null ? ` · <b>Maliyet:</b> ~$${Number(r.meta.costUsd).toFixed(4)}` : ''}${r.meta.llmCalls != null ? ` · ${r.meta.llmCalls} LLM çağrısı` : ''}</div>
  <div class="disc">${esc(r.disclaimer)}</div>
  <div class="sum">
    <div><span class="risk">Genel risk: ${esc(RISK_LABEL[r.overallRisk] ?? r.overallRisk)}</span> <span style="color:#94a3b8;font-size:11px">(yalnız kanıtlı bulgulardan; belirsiz/elenen şişirmez)</span></div>
  </div>
  <div class="sum">
    <div><b style="color:#15803d">${r.counts.kanitli}</b>Kanıtlı</div>
    <div><b style="color:#a16207">${r.counts.belirsiz}</b>İnceleme gerektiren</div>
    <div><b style="color:#64748b">${r.eliminated}</b>Elenen (hayalet)</div>
    <div><b style="color:#334155">${r.counts.artifacts}</b>Ham artefakt</div>
  </div>

  <h2>Kanıtlı bulgular (${r.proven.length})</h2>
  <ul>${r.proven.map((f) => finding(f, '#16a34a')).join('') || '<li style="color:#64748b;font-style:italic">Kanıtlı bulgu yok.</li>'}</ul>

  <h2>İnceleme gerektiren — belirsiz (${r.needsReview.length})</h2>
  <p style="font-size:12px;color:#64748b;margin:0 0 8px">Ham artefaktı olan ama kesin deterministik imzası olmayan iddialar. Silinmemiştir; insan doğrulaması önerilir.</p>
  <ul>${r.needsReview.map((f) => finding(f, '#d97706')).join('') || '<li style="color:#64748b;font-style:italic">Belirsiz bulgu yok.</li>'}</ul>

  <h2>Elenen (hayalet): ${r.eliminated}</h2>
  <p style="font-size:12px;color:#64748b;margin:0">Ajanın iddia ettiği ama hiçbir ham kanıtı bulunmayan bulgular elendi ve rapora ALINMADI.</p>
</body></html>`;
}
