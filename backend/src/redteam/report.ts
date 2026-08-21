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

export type BinderEvidence = { artifactRef: string; signature: string; detail: string; rawExcerpt?: string; command?: string };

/** Kategori → iş-etkisi + önerilen düzeltme + referans (deterministik; LLM YOK). */
export const REMEDIATION: Record<string, { label: string; desc: string; impact: string; fix: string; cwe: string; owasp: string }> = {
  sqli: { label: 'SQL Enjeksiyonu', desc: 'Kullanıcı girdisi SQL sorgusuna doğrudan katılıyor; saldırgan sorgu mantığını değiştirebilir.', impact: 'Veritabanı okuma/değiştirme, kimlik doğrulama atlatma, kitlesel veri sızıntısı.', fix: 'Parametreli sorgu (prepared statement) / ORM bağlama kullanın; girdi doğrulaması; DB kullanıcısına en az yetki.', cwe: 'CWE-89', owasp: 'A03:2021 Injection' },
  xss: { label: 'Yansıyan XSS', desc: 'Kullanıcı girdisi çıktıya kaçış yapılmadan yansıyor; tarayıcıda betik çalışabilir.', impact: 'Oturum çalma, kimlik avı, kullanıcı adına işlem.', fix: 'Bağlama-duyarlı çıktı kaçışı (HTML/JS/URL); Content-Security-Policy; girdi doğrulama.', cwe: 'CWE-79', owasp: 'A03:2021 Injection' },
  lfi: { label: 'Yerel Dosya Dahil Etme', desc: 'Dosya yolu kullanıcı girdisinden türetiliyor; sunucu dosyaları okunabiliyor.', impact: 'Yapılandırma/kimlik dosyaları sızıntısı; bazen kod çalıştırma.', fix: 'Dosya yolunu allowlist ile eşleyin; ".." temizleyin; kök-dizin hapsi (chroot/realpath).', cwe: 'CWE-22', owasp: 'A01:2021 Broken Access Control' },
  path_traversal: { label: 'Dizin Geçişi', desc: 'Girdi ile dizin sınırının dışına çıkılabiliyor (../).', impact: 'İzinsiz dosya okuma/yazma.', fix: 'Kanonik yol doğrulama (realpath) + kök-dizin hapsi; girdi allowlist.', cwe: 'CWE-22', owasp: 'A01:2021 Broken Access Control' },
  rce: { label: 'Uzaktan Kod Çalıştırma', desc: 'Girdi bir komut/kod bağlamına giriyor; saldırgan sunucuda kod çalıştırabilir.', impact: 'Sunucunun tam ele geçirilmesi.', fix: 'Kullanıcı girdisini komuta koymayın; güvenli API/allowlist; sandbox; en az yetki.', cwe: 'CWE-94', owasp: 'A03:2021 Injection' },
  ssrf: { label: 'Sunucu-Taraflı İstek Sahteciliği', desc: 'Sunucu, kullanıcı-kontrollü bir URL’i çekiyor.', impact: 'İç ağ/metadata erişimi, port tarama, veri sızıntısı.', fix: 'Hedef URL allowlist; iç IP/metadata engeli; DNS-rebinding koruması.', cwe: 'CWE-918', owasp: 'A10:2021 SSRF' },
  info_disclosure: { label: 'Bilgi İfşası', desc: 'Ayrıntılı hata/yığın izi ya da iç bilgi dışarı sızıyor.', impact: 'İç yapı/teknoloji ifşası; sonraki saldırılara zemin.', fix: 'Üretimde ayrıntılı hataları kapatın; genel hata mesajı; teknoloji başlıklarını gizleyin.', cwe: 'CWE-200', owasp: 'A05:2021 Security Misconfiguration' },
  xxe: { label: 'XML Dış Varlık', desc: 'XML ayrıştırıcı dış varlıkları çözüyor.', impact: 'Dosya okuma, SSRF, hizmet reddi.', fix: 'XML ayrıştırıcıda dış varlıkları/DTD’yi kapatın.', cwe: 'CWE-611', owasp: 'A05:2021 Security Misconfiguration' },
  open_redirect: { label: 'Açık Yönlendirme', desc: 'Yönlendirme hedefi doğrulanmadan kullanıcı girdisinden alınıyor.', impact: 'Kimlik avı, güven kötüye kullanımı.', fix: 'Yönlendirme hedefini allowlist ile doğrulayın; göreli yol kullanın.', cwe: 'CWE-601', owasp: 'A01:2021 Broken Access Control' },
  bilinmeyen: { label: 'Genel Bulgu', desc: 'Kategori kesin sınıflandırılamadı; ham kanıta göre değerlendirilmeli.', impact: 'Bağlama göre değişir.', fix: 'İlgili güvenlik kontrolünü uygulayın; ham kanıtı inceleyin.', cwe: '-', owasp: '-' },
};
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
  eliminatedReasons?: Record<string, number>; // {off-target,no-evidence,weak-signature} — panel kırılımı
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
  eliminatedReasons?: Record<string, number>; // panel kırılımı (rapora değil): off-target/no-evidence/weak-signature
  disclaimer: string;
  // (BAĞIMSIZ WATCHDOG — D5) Koşu cap/watchdog tarafından ZORLA durdurulduysa dürüst not (yarım kalan
  // istek/yanıt çiftleri zaten P0-2 kuralı gereği kanıt sayılmaz — rapor bozulmaz, yalnız şeffaf bir not eklenir).
  stoppedReason?: string;
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
    eliminatedReasons: binder.eliminatedReasons ?? {},
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

/** Yapısal rapor → TAM, kendi-kendine yeten PROFESYONEL HTML dokümanı (panelde "Raporu Gör" + PDF).
 *  Deterministik paket görsel diliyle uyumlu (şiddet renkleri, düzeltme kutuları) — AMA "deneysel/
 *  deterministik-değil" disclaimer'ı prominent korunur; risk yalnız kanıtlıdan; üç-katman dürüstlüğü. */
export function renderRedTeamFullHtml(r: RedTeamReport): string {
  const esc = (s: string) => String(s ?? '').replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]!));
  const SEVC: Record<string, string> = { kritik: '#b91c1c', yüksek: '#c2410c', orta: '#a16207', düşük: '#15803d', temiz: '#15803d' };
  const rc = SEVC[r.overallRisk] ?? '#334155';
  const posture = r.proven.length === 0
    ? 'Bu koşuda kanıtlı bulgu üretilmedi — hedef, otonom ajanın denediği tekniklere karşı gözlemlenen kanıt üretmedi.'
    : `${r.proven.length} kanıtlı bulgu ham kanıta bağlandı. Genel risk yalnız bu kanıtlı bulgulardan türetildi (belirsiz/elenen şişirmez).`;

  const card = (f: BinderFinding, needsHuman: boolean) => {
    const rem = REMEDIATION[f.category] ?? REMEDIATION.bilinmeyen;
    const sc = SEVC[f.severity] ?? '#334155';
    const ev = f.evidence;
    return `<div class="fcard">
      <div class="fhead">
        <span class="sev" style="background:${sc}">${esc((RISK_LABEL[f.severity] ?? f.severity)).toUpperCase()}</span>
        <span class="ftitle">${esc(f.title)}</span>
        ${needsHuman ? '<span class="human">İNSAN DOĞRULAMASI GEREKİR</span>' : ''}
      </div>
      <table class="fmeta"><tbody>
        <tr><th>Etkilenen uç-nokta</th><td>${f.endpoint ? `<code>${esc(f.endpoint)}</code>` : '—'}</td></tr>
        <tr><th>Kategori</th><td>${esc(rem.label)} <span class="ref">${esc(rem.cwe)} · ${esc(rem.owasp)}</span></td></tr>
        <tr><th>Açıklama</th><td>${esc(rem.desc)}</td></tr>
        <tr><th>İş etkisi</th><td>${esc(rem.impact)}</td></tr>
        <tr><th>Doğrulama</th><td>${esc(f.reason)}${ev?.signature ? ` · imza: <code>${esc(ev.signature)}</code>` : ''}</td></tr>
      </tbody></table>
      ${ev && (ev.rawExcerpt || ev.command) ? `<div class="evbox">
        <div class="evlabel">HAM KANIT ${ev.artifactRef ? `<span class="ref">${esc(ev.artifactRef)}</span>` : ''} <span class="reddot">hassas veri redakte</span></div>
        ${ev.command ? `<pre class="cmd">$ ${esc(ev.command)}</pre>` : ''}
        ${ev.rawExcerpt ? `<pre class="raw">${esc(ev.rawExcerpt)}</pre>` : ''}
      </div>` : ''}
      <div class="fix"><b>Önerilen Düzeltme</b><br>${esc(rem.fix)}</div>
    </div>`;
  };

  return `<!doctype html><html lang="tr"><head><meta charset="utf-8"><title>Otonom AI Red Team — Bulgu Raporu</title>
<style>
  *{box-sizing:border-box} body{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#0f172a;margin:0;padding:26px 30px;line-height:1.5;font-size:13px}
  h1{font-size:22px;margin:0 0 2px} h2{font-size:15px;margin:24px 0 10px;color:#123f3a;border-bottom:2px solid #123f3a;padding-bottom:5px}
  .meta{font-size:12px;color:#475569;margin-bottom:12px}
  .disc{background:#fff7ed;border:1px solid #fb923c;border-left:5px solid #ea580c;border-radius:8px;padding:12px 14px;font-size:12px;color:#7c2d12;margin:0 0 16px;font-weight:500}
  .risk{display:inline-block;padding:4px 14px;border-radius:999px;color:#fff;font-weight:700;background:${rc}}
  .exec{background:#f0f7f5;border:1px solid #cfe3dd;border-radius:8px;padding:14px 16px;margin:0 0 6px}
  .sum{display:flex;gap:22px;flex-wrap:wrap;font-size:13px;margin:10px 0}
  .sum div{text-align:center} .sum b{font-size:20px;display:block}
  .fcard{border:1px solid #e2e8f0;border-radius:10px;padding:0;margin:0 0 16px;overflow:hidden;box-shadow:0 1px 2px rgba(0,0,0,.04)}
  .fhead{display:flex;align-items:center;gap:10px;padding:10px 14px;background:#f8fafc;border-bottom:1px solid #e2e8f0}
  .sev{color:#fff;font-weight:800;font-size:11px;padding:3px 9px;border-radius:5px;letter-spacing:.4px}
  .ftitle{font-weight:700;font-size:14px;color:#0f172a;flex:1}
  .human{background:#fef3c7;color:#92400e;font-weight:700;font-size:10px;padding:3px 8px;border-radius:5px;border:1px solid #fcd34d}
  table.fmeta{width:100%;border-collapse:collapse;font-size:12px} .fmeta th{text-align:left;width:130px;color:#64748b;font-weight:600;padding:6px 14px;vertical-align:top;white-space:nowrap} .fmeta td{padding:6px 14px;color:#1e293b}
  .ref{font-size:11px;color:#64748b} code{background:#eef2f7;padding:1px 5px;border-radius:4px;font-size:11px}
  .evbox{margin:6px 14px 10px;background:#0b1120;border-radius:8px;padding:8px 10px}
  .evlabel{color:#7dd3fc;font-size:11px;font-weight:700;margin-bottom:5px;letter-spacing:.3px}
  .reddot{color:#fca5a5;font-weight:600;font-size:10px;margin-left:6px}
  pre.cmd{color:#a3e635;margin:0 0 4px;font-size:11px;white-space:pre-wrap;word-break:break-all}
  pre.raw{color:#cbd5e1;margin:0;font-size:11px;white-space:pre-wrap;word-break:break-word;max-height:260px;overflow:auto}
  .fix{margin:0 14px 12px;background:#ecfdf5;border:1px solid #a7f3d0;border-left:5px solid #059669;border-radius:6px;padding:9px 12px;font-size:12px;color:#065f46}
  .empty{color:#64748b;font-style:italic;padding:8px 0}
  table.scope{width:100%;border-collapse:collapse;font-size:12px;margin-top:6px} .scope th,.scope td{border:1px solid #e2e8f0;padding:6px 10px;text-align:left} .scope th{background:#f1f5f9;color:#475569;width:180px}
</style></head><body>
  <h1>Otonom AI Red Team — Bulgu Raporu</h1>
  <div class="meta"><b>Hedef:</b> ${esc(r.meta.target)} · <b>Seviye:</b> ${esc(r.meta.level)} · <b>Ortam:</b> ${esc(r.meta.environment)} · <b>Tarih:</b> ${esc(r.meta.generatedAt)}${r.meta.costUsd != null ? ` · <b>Maliyet:</b> ~$${Number(r.meta.costUsd).toFixed(4)}` : ''}${r.meta.llmCalls != null ? ` · ${r.meta.llmCalls} LLM çağrısı` : ''}</div>
  <div class="disc">⚠ DENEYSEL · DETERMİNİSTİK DEĞİL · resmi denetim/sertifikasyon DEĞİL. ${esc(r.disclaimer)}</div>
  ${r.stoppedReason ? `<div class="disc" style="background:#fef2f2;border-color:#f87171;border-left-color:#dc2626;color:#7f1d1d">⏱ KOŞU ZORLA DURDURULDU: ${esc(r.stoppedReason)}</div>` : ''}

  <h2>Yönetici Özeti</h2>
  <div class="exec">
    <p style="margin:0 0 8px"><b>Ne test edildi:</b> Otonom bir yapay-zekâ ajanı (PentAGI), <b>${esc(r.meta.target)}</b> hedefini <b>${esc(r.meta.level)}</b> profilinde, izole ve cap-sınırlı bir ortamda gerçek saldırı teknikleriyle sınadı.</p>
    <p style="margin:0 0 8px"><b>Nasıl çalışır (kanıt-bağlama):</b> Her iddia, ajanın SÖZÜNE değil saklanan HAM kanıta (gerçek istek/yanıt, terminal çıktısı) bağlanır. Deterministik imza varsa <b>kanıtlı</b>; kanıt var ama imza yoksa <b>inceleme gerektiren</b>; hiç izi yoksa (ya da hedef-dışı) <b>elenir</b>.</p>
    <p style="margin:0"><b>Genel duruş:</b> ${esc(posture)}</p>
    <div class="sum">
      <div><span class="risk">Genel risk: ${esc(RISK_LABEL[r.overallRisk] ?? r.overallRisk)}</span></div>
      <div><b style="color:#15803d">${r.counts.kanitli}</b>Kanıtlı</div>
      <div><b style="color:#a16207">${r.counts.belirsiz}</b>İnceleme gerektiren</div>
      <div><b style="color:#64748b">${r.eliminated}</b>Elenen (hayalet)</div>
      <div><b style="color:#334155">${r.counts.artifacts}</b>Ham artefakt</div>
    </div>
  </div>

  <h2>Kanıtlı Bulgular (${r.proven.length})</h2>
  ${r.proven.length ? r.proven.map((f) => card(f, false)).join('') : '<p class="empty">Kanıtlı bulgu yok — bu koşuda ham kanıta bağlanan doğrulanmış bir zafiyet üretilmedi.</p>'}

  <h2>İnceleme Gerektiren — Belirsiz (${r.needsReview.length})</h2>
  <p style="font-size:12px;color:#64748b;margin:0 0 10px">Ham artefaktı olan ama kesin deterministik imzası olmayan iddialar. Silinmemiştir; <b>insan doğrulaması</b> önerilir. Genel riski ETKİLEMEZ.</p>
  ${r.needsReview.length ? r.needsReview.map((f) => card(f, true)).join('') : '<p class="empty">İnceleme gerektiren bulgu yok.</p>'}

  <h2>Elenen — Hayalet (${r.eliminated})</h2>
  <p style="font-size:12px;color:#64748b;margin:0">Ajanın iddia ettiği ama <b>hiçbir ham kanıtı bulunmayan</b> ya da <b>hedef-dışı host</b> referanslayan bulgular elendi ve rapora ALINMADI (detay verilmez — kanıtı yoktur). Bu, yanlış-pozitifi ve ajanın eğitim-bilgisi sızıntısını önleyen kasıtlı bir dürüstlük kuralıdır.</p>

  <h2>Metodoloji ve Kapsam</h2>
  <table class="scope"><tbody>
    <tr><th>Motor</th><td>Otonom PentAGI ajanı — gerçek saldırı teknikleri (simülasyon değil)</td></tr>
    <tr><th>Kanıt-bağlama</th><td>Üç katman: kanıtlı (deterministik imza) / belirsiz (insan-inceleme) / hayalet (elenir)</td></tr>
    <tr><th>İzolasyon</th><td>Efemer izole droplet; egress yalnız yetkili hedef + LLM; CyberTestify/dış/metadata engelli (ampirik doğrulandı)</td></tr>
    <tr><th>Provenance</th><td>Yalnız pinlenen hedefe (${esc(r.meta.target)}) ait bulgular; hedef-dışı host referansları elenir</td></tr>
    <tr><th>Bütçe</th><td>Sert cap (token/süre/maliyet); aşımda ağ-katmanı hard-stop${r.meta.costUsd != null ? ` — bu koşu ~$${Number(r.meta.costUsd).toFixed(4)}` : ''}</td></tr>
    <tr><th>Yetki</th><td>Sahiplik/yetki beyanı + risk onayı ile; ${esc(r.meta.environment)} ortamı</td></tr>
  </tbody></table>

  <p style="margin-top:20px;font-size:11px;color:#94a3b8;border-top:1px solid #e2e8f0;padding-top:10px">Bu rapor deneysel otonom red-team katmanı tarafından üretilmiştir ve deterministik değildir; resmi bir güvenlik denetimi ya da uygunluk belgesi yerine geçmez. Kanıtlı bulgular ham kanıta bağlıdır; belirsiz bulgular insan doğrulaması bekler.</p>
</body></html>`;
}
