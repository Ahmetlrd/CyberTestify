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

export type BinderEvidence = { artifactRef: string; signature: string; detail: string; rawExcerpt?: string; command?: string; marker?: string; missing?: string[] };

// (P0-9) Çerez bayrağı → YALNIZ o bayrağın gerçek riski (jenerik "hepsi eksik" listesi DEĞİL).
const COOKIE_FLAG_IMPACT: Record<string, string> = {
  HttpOnly: 'JavaScript ile çerez okunabilir — XSS ile oturum çerezi çalınabilir',
  Secure: 'Çerez şifresiz (HTTP) kanalda da gönderilir — ağ dinleyicisi oturumu ele geçirebilir',
  SameSite: 'Tarayıcı çerezi farklı-site isteklerinde otomatik gönderebilir — Cross-Site Request Forgery (CSRF) yüzeyi artar',
};

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
  security_header: { label: 'Eksik Güvenlik Başlığı', desc: 'Yanıt, tarayıcı-tarafı korumaları sağlayan güvenlik başlıklarını içermiyor.', impact: 'Clickjacking, MIME-sniffing, karışık-içerik ve XSS etkisinin artması.', fix: 'X-Frame-Options/CSP frame-ancestors, X-Content-Type-Options: nosniff, HTTPS’te Strict-Transport-Security ve uygun bir Content-Security-Policy ekleyin.', cwe: 'CWE-693', owasp: 'A05:2021 Security Misconfiguration' },
  cookie_config: { label: 'Çerez Güvenlik Bayrağı Eksik', desc: 'Oturum/kimlik çerezi HttpOnly/Secure/SameSite bayraklarından biri veya birkaçı olmadan ayarlanıyor.', impact: 'JS ile çerez okunması (XSS), şifresiz kanalda sızma, CSRF yüzeyi.', fix: 'Oturum çerezlerini HttpOnly + Secure + SameSite=Lax/Strict ile ayarlayın.', cwe: 'CWE-1004', owasp: 'A05:2021 Security Misconfiguration' },
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
  filteredMeta?: number;
  tried?: { httpRequests?: number; terminalArtifacts?: number; endpointCount?: number; endpoints?: string[]; families?: string[] };
  overallRisk: 'kritik' | 'yüksek' | 'orta' | 'düşük' | 'temiz';
  findings: BinderFinding[];
};

export type TriedSummary = NonNullable<BinderOutput['tried']>;

export type RedTeamReportMeta = {
  target: string;
  level: 'S1' | 'S2' | 'S3';
  environment: 'test' | 'staging' | 'prod';
  generatedAt: string; // ISO — çağıran verir (deterministik render; modül saat okumaz)
  costUsd?: number | null;
  llmCalls?: number | null;
  agentSec?: number | null;   // (P0-5) yalnız ajan (campaign) süresi
  elapsedSec?: number | null; // (P0-5) toplam wall-clock süre (infra dahil)
  reportNo?: string | null;   // (P0-C) CT-RT-YYYYMMDD-XXXX — çağıran verir; yoksa meta'dan türetilir
  jobId?: string | null;      // (P0-C) rapor no türetiminde stabil sonek kaynağı (müşteriye gösterilmez)
};

/** (P0-C) Kurumsal rapor numarası: CT-RT-YYYYMMDD-XXXX. Deterministik (saat okumaz) — meta.reportNo
 *  verilmişse onu, yoksa generatedAt tarihi + (jobId/target) stabil 4-hane sonekinden türetir. */
export function redteamReportNo(meta: { reportNo?: string | null; generatedAt: string; jobId?: string | null; target: string }): string {
  if (meta.reportNo) return meta.reportNo;
  const ymd = String(meta.generatedAt || '').slice(0, 10).replace(/-/g, '') || '00000000';
  const seed = String(meta.jobId || meta.target || '');
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
  const suffix = h.toString(36).toUpperCase().padStart(4, '0').slice(-4);
  return `CT-RT-${ymd}-${suffix}`;
}

export type RedTeamReport = {
  meta: RedTeamReportMeta;
  overallRisk: BinderOutput['overallRisk'];
  counts: BinderOutput['summary'] & { artifacts: number };
  proven: BinderFinding[];      // KANITLI
  needsReview: BinderFinding[]; // BELİRSİZ
  eliminated: number;           // HAYALET (yalnız sayı)
  eliminatedReasons?: Record<string, number>; // panel kırılımı (rapora değil): off-target/no-evidence/weak-signature
  tried?: BinderOutput['tried']; // P0-2 'Pozitif güvence' + P1 exec (gerçek sayaçlar)
  filteredMeta?: number;
  disclaimer: string;
  // (BAĞIMSIZ WATCHDOG — D5) Koşu cap/watchdog tarafından ZORLA durdurulduysa dürüst not (yarım kalan
  // istek/yanıt çiftleri zaten P0-2 kuralı gereği kanıt sayılmaz — rapor bozulmaz, yalnız şeffaf bir not eklenir).
  stoppedReason?: string;
  // (P2/FIX#4 — DÜRÜST SAĞLIK NOTU) Hedef geçerli bir HTTP yanıtı vermediyse (yavaş/kısıtlı/asılı → tüm
  // istekler timeout) "kanıtlı yok = Temiz = güvenli" YANILGISINI önle. overallRisk'i şişirmez/değiştirmez;
  // yalnız şeffaf bir uyarı ekler (üç-durum dürüstlüğü: test edilebilir yüzey ALINAMADI).
  healthNote?: string;
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
    tried: binder.tried,
    filteredMeta: binder.filteredMeta,
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
const NEXT_STEP: Record<string, string> = {
  xss: 'Etkilenen parametrede çıktı-kodlaması (context-aware output encoding) uygulayın ve bir Content-Security-Policy ekleyin; ardından aynı uç-noktayı manuel/otomatik yeniden test edin.',
  sqli: 'Etkilenen sorguyu parametreli (prepared statement) hale getirin ve girdiyi doğrulayın; ardından SQLi’ye özel derin bir test (ör. sqlmap ile yetkili kapsamda) planlayın.',
  idor: 'Nesne erişiminde sunucu-tarafı yetki kontrolü (ownership check) ekleyin; benzer tüm uç-noktaları yetki matrisine göre gözden geçirin.',
  info_disclosure: 'Sürüm/teknoloji bilgisini yanıt başlıklarından ve hata sayfalarından kaldırın; üretim ortamında ayrıntılı hata/izleme çıktısını kapatın.',
  security_header: 'Eksik güvenlik başlıklarını (CSP, X-Frame-Options, X-Content-Type-Options, HSTS) ekleyin ve bir tarama ile teyit edin.',
  cookie_config: 'Oturum çerezlerine HttpOnly + Secure + SameSite bayraklarını ekleyin ve tüm kimlik/oturum çerezlerini gözden geçirin.',
  bilinmeyen: 'İlgili ham kanıtı bir güvenlik uzmanına doğrulatın ve uygun güvenlik kontrolünü uygulayın.',
};

// (P0-B) 'customer' = satılabilir müşteri belgesi: iç-operasyon verileri (maliyet, LLM sayısı, süre,
// artefakt-ID, IP/droplet, eleme kırılımı, model adı) GİZLENİR. 'admin' = tam iç görünüm (hiçbir şey
// silinmez — reportJson'da hepsi durur; yalnız müşteri render'ında saklanır). Varsayılan: customer.
export type RedTeamReportMode = 'customer' | 'admin';
export function renderRedTeamFullHtml(r: RedTeamReport, mode: RedTeamReportMode = 'customer'): string {
  const admin = mode === 'admin';
  const esc = (s: string) => String(s ?? '').replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]!));
  // SEVC = GENEL RİSK rozeti (kapak + özet). Semantiği farklıdır: "düşük/temiz duruş" İYİdir -> yeşil.
  // DEĞİŞTİRİLMEDİ.
  const SEVC: Record<string, string> = { kritik: '#b91c1c', yüksek: '#c2410c', orta: '#a16207', düşük: '#15803d', temiz: '#15803d' };
  // (GÖRSEL TUTARLILIK) BULGU KARTI şiddet rozeti — diğer 6 paketin paletiyle AYNI (pdf.ts sev-*).
  // Neden ayrı map: eski palette "düşük" bulgu YEŞİL basılıyordu; müşteri bunu "temiz" sanıyordu ve
  // "orta" tonu (#a16207) amber kapsam-uyarı kutularıyla neredeyse aynı renkti -> rutin not ile
  // gerçek bulgu ayrışmıyordu. Genel-risk rozeti bu değişiklikten ETKİLENMEZ.
  const FIND_SEVC: Record<string, string> = { kritik: '#B3261E', yüksek: '#D64545', orta: '#E0940E', düşük: '#9AA0A6', temiz: '#5FA396' };
  const rc = SEVC[r.overallRisk] ?? '#334155';
  const t = r.tried ?? {};
  const reportNo = redteamReportNo(r.meta);
  const posture = r.proven.length === 0
    ? 'Bu koşuda kanıtlı bulgu üretilmedi — hedef, otonom ajanın denediği tekniklere karşı gözlemlenen kanıt üretmedi.'
    : `${r.proven.length} kanıtlı bulgu ham kanıta bağlandı. Genel risk yalnız bu kanıtlı bulgulardan türetildi (belirsiz/elenen şişirmez).`;

  // P1 — "ne denendi (sayılarla)" cümlesi, orkestratörün gerçek sayaçlarından (uydurma yok).
  const triedSentence = (() => {
    const parts: string[] = [];
    if (t.httpRequests != null) parts.push(`${t.httpRequests} HTTP isteği`);
    if (t.endpointCount != null) parts.push(`${t.endpointCount} uç-nokta`);
    if (t.families?.length) parts.push(`${t.families.length} teknik ailesi (${t.families.map(esc).join(', ')})`);
    return parts.length ? parts.join(' · ') : 'ölçülebilir HTTP etkileşimi kaydedilmedi';
  })();

  // P1 — önerilen sonraki adım (ŞABLON, LLM değil): en yüksek şiddetli kanıtlı bulgudan türetilir.
  const nextStep = (() => {
    if (r.proven.length) {
      const order = ['kritik', 'yüksek', 'orta', 'düşük'];
      const top = [...r.proven].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity))[0];
      return NEXT_STEP[top.category] ?? NEXT_STEP.bilinmeyen;
    }
    if (r.needsReview.length) return 'İnceleme gerektiren bulguları bir güvenlik uzmanına doğrulatın; teyit edilenler için ilgili düzeltmeyi uygulayın.';
    return 'Bu koşuda kanıtlı bulgu çıkmadı; kapsamı genişletmek için kimlikli/yetkili bir tarama ya da manuel bir güvenlik incelemesi değerlendirilebilir.';
  })();

  // P0-3 — Kanıt kutusu: marker (imza) satırını ve çevresindeki 5-15 satırı vurgulu göster (dump değil).
  const evSnippet = (raw: string, signature?: string): string => {
    const lines = raw.replace(/\r/g, '').split('\n');
    let hit = -1;
    if (signature) {
      const needle = signature.toLowerCase();
      hit = lines.findIndex((ln) => ln.toLowerCase().includes(needle));
    }
    let start: number, end: number;
    if (hit >= 0) { start = Math.max(0, hit - 6); end = Math.min(lines.length, hit + 7); }
    else { start = 0; end = Math.min(lines.length, 14); }
    const truncatedTop = start > 0;
    const truncatedBot = end < lines.length;
    const body = lines.slice(start, end).map((ln, i) => {
      const isHit = start + i === hit;
      const shown = ln.length > 400 ? ln.slice(0, 400) + ' …' : ln;
      return isHit
        ? `<span class="hit">${esc(shown) || ' '}</span>`
        : esc(shown);
    }).join('\n');
    return `${truncatedTop ? '<span class="elide">  ⋮ (önceki satırlar kısaltıldı)</span>\n' : ''}${body}${truncatedBot ? '\n<span class="elide">  ⋮ (sonraki satırlar kısaltıldı)</span>' : ''}`;
  };

  // (P0-B MÜŞTERİ) Kanıt komutunu müşteri için temizle: --resolve host:port:IP (hedefin pinlenen IP'si),
  // --connect-timeout, --max-time = bağlantı/altyapı plumbing'i → müşteri PDF'inde IP/timeout GİZLENİR.
  // Kanıtın ANLAMI (yöntem + URL + payload + yansıyan gövde) korunur; yalnız iç bağlantı detayı düşer.
  const custCmd = (cmd: string): string => admin ? cmd : String(cmd || '')
    .replace(/\s--resolve\s+\S+/g, '')
    .replace(/\s--connect-timeout\s+\d+/g, '')
    .replace(/\s--max-time\s+\d+/g, '')
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '•••')   // kalan çıplak IPv4 → maskele
    .replace(/\s{2,}/g, ' ').trim();

  const CONFIG_CATS = new Set(['cookie_config', 'security_header', 'info_disclosure']);
  const card = (f: BinderFinding, needsHuman: boolean) => {
    const rem = REMEDIATION[f.category] ?? REMEDIATION.bilinmeyen;
    const sc = FIND_SEVC[f.severity] ?? '#334155';
    const ev = f.evidence;
    // (P0-2b) Config bulgularında Açıklama = HAM KANIT'ten okunan SPESİFİK gözlem (hangi bayrak/başlık
    // gerçekten eksik), jenerik "biri/birkaçı eksik" şablonu DEĞİL. Diğer bulgularda kategori açıklaması.
    const specific = CONFIG_CATS.has(f.category) && ev?.detail ? ev.detail : null;
    // (P0-9) İŞ ETKİSİ de flag-spesifik: çerez bulgusunda YALNIZ gerçekten eksik bayrağın riski yazılır
    // (HttpOnly/Secure zaten mevcutsa onların riski gösterilmez — jenerik XSS/şifresiz-kanal listesi DEĞİL).
    const impact = (f.category === 'cookie_config' && ev?.missing?.length)
      ? ev.missing.map((m) => COOKIE_FLAG_IMPACT[m]).filter(Boolean).join('; ') || rem.impact
      : rem.impact;
    return `<div class="fcard" style="border-left:4px solid ${sc}">
      <div class="fhead">
        <span class="sev" style="background:${sc}">${esc((RISK_LABEL[f.severity] ?? f.severity)).toUpperCase()}</span>
        <span class="ftitle">${esc(f.title)}</span>
        ${needsHuman ? '<span class="human">İNSAN DOĞRULAMASI GEREKİR</span>' : ''}
      </div>
      <table class="fmeta"><tbody>
        <tr><th>Etkilenen uç-nokta</th><td>${f.endpoint ? `<code>${esc(f.endpoint)}</code>` : '—'}</td></tr>
        <tr><th>Kategori</th><td>${esc(rem.label)} <span class="ref">${esc(rem.cwe)} · ${esc(rem.owasp)}</span></td></tr>
        <tr><th>Açıklama</th><td>${esc(specific ?? rem.desc)}</td></tr>
        ${specific ? `<tr><th>Kategori bilgisi</th><td>${esc(rem.desc)}</td></tr>` : ''}
        <tr><th>İş etkisi</th><td>${esc(impact)}</td></tr>
        <tr><th>Doğrulama</th><td>${esc(f.reason)}${ev?.signature ? ` · imza: <code>${esc(ev.signature)}</code>` : ''}</td></tr>
      </tbody></table>
      ${ev && (ev.rawExcerpt || ev.command) ? `<div class="evbox">
        <div class="evlabel">HAM KANIT ${admin && ev.artifactRef ? `<span class="ref">${esc(ev.artifactRef)}</span>` : ''}${ev.marker ? ` <span class="mk">marker: ${esc(ev.marker)}</span>` : (ev.signature ? ` <span class="mk">imza: ${esc(ev.signature)}</span>` : '')} <span class="reddot">hassas veri redakte</span></div>
        ${ev.command ? `<pre class="cmd">$ ${esc(custCmd(ev.command))}</pre>` : ''}
        ${ev.rawExcerpt ? `<pre class="raw">${evSnippet(admin ? ev.rawExcerpt : ev.rawExcerpt.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '•••'), ev.marker || ev.signature)}</pre>` : ''}
      </div>` : ''}
      <div class="fix"><b>Önerilen Düzeltme</b><br>${esc(rem.fix)}</div>
    </div>`;
  };

  return `<!doctype html><html lang="tr"><head><meta charset="utf-8"><title>Otonom AI Red Team — Bulgu Raporu</title>
<style>
  *{box-sizing:border-box} body{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#0f172a;margin:0;padding:26px 30px;line-height:1.5;font-size:13px}
  h1{font-size:22px;margin:0 0 2px} h2{font-size:15px;margin:24px 0 10px;color:#123f3a;border-bottom:2px solid #123f3a;padding-bottom:5px}
  .meta{font-size:12px;color:#475569;margin-bottom:12px}
  /* (GÖRSEL AYRIM) Rutin kapsam/uyarı şeridi AMBER ailededir; bulgu şiddet rozetleri KIRMIZI
     ailededir. Eskiden ikisi de turuncu-kırmızı tondaydı ve "deneysel" uyarısı ciddi bir bulgu
     gibi okunuyordu. (Koşu durduruldu / hedef yanıt vermedi gibi GERÇEK alarmlar satır-içi
     kendi kırmızı/amber rengini yazmaya devam eder — onlar rutin not değil.) */
  .disc{background:#FDF5E6;border:1px solid #F5C77A;border-left:5px solid #E8912B;border-radius:8px;padding:12px 14px;font-size:12px;color:#7A4B12;margin:0 0 16px;font-weight:500}
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
  pre.raw{color:#cbd5e1;margin:0;font-size:11px;white-space:pre-wrap;word-break:break-word;max-height:300px;overflow:auto;line-height:1.55}
  pre.raw .hit{display:inline-block;width:100%;background:#facc15;color:#0b1120;font-weight:700;padding:1px 4px;border-radius:3px}
  pre.raw .elide{color:#64748b;font-style:italic}
  .mk{color:#fde68a;font-size:10px;font-weight:700;margin-left:6px}
  .assur{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:8px 0 4px}
  .assur .ac{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:10px 12px;text-align:center}
  .assur .ac b{display:block;font-size:20px;color:#123f3a} .assur .ac span{font-size:11px;color:#64748b}
  .chips{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0} .chips code{background:#eef2f7;padding:2px 7px;border-radius:5px;font-size:11px}
  ul.lim{margin:6px 0 0;padding-left:18px;font-size:12px;color:#475569} ul.lim li{margin:3px 0}
  .fix{margin:0 14px 12px;background:#ecfdf5;border:1px solid #a7f3d0;border-left:5px solid #059669;border-radius:6px;padding:9px 12px;font-size:12px;color:#065f46}
  .empty{color:#64748b;font-style:italic;padding:8px 0}
  table.scope{width:100%;border-collapse:collapse;font-size:12px;margin-top:6px} .scope th,.scope td{border:1px solid #e2e8f0;padding:6px 10px;text-align:left} .scope th{background:#f1f5f9;color:#475569;width:180px}
  /* (P0-C) TAM SAYFA KAPAK — teal #123F3A + amber #F5A623; içerik dikey ortalı, uyarı en altta. */
  .cover{page-break-after:always;min-height:960px;display:flex;flex-direction:column;padding:0}
  .cover-band{background:linear-gradient(135deg,#123F3A 0%,#0A2E2A 100%);color:#EEF5F3;padding:34px;display:flex;align-items:center;gap:16px}
  .cover-band .logo{width:48px;height:48px;flex:0 0 48px}
  .cover-band .brand{font-size:26px;font-weight:800;letter-spacing:.3px;color:#fff;line-height:1.1}
  .cover-band .brand span{color:#F5A623}
  .cover-band .rtype{font-size:12px;color:#9Fc4bc;margin-top:4px;letter-spacing:.5px;text-transform:uppercase}
  .cover-body{flex:1;display:flex;flex-direction:column;justify-content:center;gap:26px;padding:20px 44px}
  .cover-target-k{color:#5FA396;text-transform:uppercase;letter-spacing:1px;font-size:11px;font-weight:700}
  .cover-target{color:#123F3A;font-size:38px;font-weight:800;line-height:1.15;word-break:break-word;margin-top:4px}
  .cover-badges{display:flex;flex-wrap:wrap;gap:10px}
  .cbadge{font-size:13px;font-weight:700;padding:7px 16px;border-radius:14px}
  .cbadge-lvl{background:#123F3A;color:#fff} .cbadge-env{background:#EEF5F3;color:#123F3A;border:1px solid #DCEAE6} .cbadge-risk{color:#fff}
  .cover-info{display:flex;gap:44px;border-top:1px solid #DCEAE6;border-bottom:1px solid #DCEAE6;padding:16px 0}
  .cover-info .k{display:block;color:#5FA396;text-transform:uppercase;letter-spacing:.5px;font-size:9px;font-weight:700}
  .cover-info .v{display:block;color:#123F3A;font-weight:700;font-size:15px;margin-top:3px;font-variant-numeric:tabular-nums}
  .cover-counts{display:flex;gap:14px;flex-wrap:wrap}
  .cover-counts .cc{flex:1;min-width:96px;border:1px solid #DCEAE6;border-radius:8px;padding:14px;text-align:center;background:#F6FAF8}
  .cover-counts .cc b{display:block;font-size:26px;color:#123F3A} .cover-counts .cc span{font-size:10.5px;color:#5FA396;text-transform:uppercase;letter-spacing:.4px}
  .cover-warn{margin:0 44px 30px;background:#FDF5E6;border:1px solid #F5C77A;border-left:4px solid #E8912B;border-radius:8px;padding:10px 14px;font-size:10.5px;color:#7A4B12}
  /* (P0-D) "Bu rapor ne değildir?" kutusu — yönetici özetinde beklenti yönetimi. */
  .notbox{background:#FDF5E6;border:1px solid #F5C77A;border-left:4px solid #E8912B;border-radius:8px;padding:12px 16px;margin:12px 0 4px}
  .notbox b{color:#8A5B08;font-size:12.5px} .notbox ul{margin:6px 0 0;padding-left:18px;font-size:11.5px;color:#7A4B12} .notbox li{margin:3px 0}
  .toc-page{page-break-after:always;padding:8px 34px 20px}
  .toc-page h2{color:#123F3A;border-bottom:2px solid #F5A623;font-size:18px}
  .toc-row{margin:9px 0;font-size:13px;border-bottom:1px dotted #E1ECE8;padding-bottom:6px;display:flex;justify-content:space-between}
  .toc-row a{color:#14514A;text-decoration:none;font-weight:600} .toc-row .tnum{color:#5FA396;font-weight:700;margin-right:8px}
</style></head><body>
  <!-- (P0-C) TAM SAYFA KAPAK — kurumsal; Rapor No mevcut; maliyet YOK; uyarı küçük/ikincil. -->
  <section class="cover">
    <div class="cover-band">
      <svg class="logo" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" fill="#F5A623"/><path d="M9 12l2 2 4-4" stroke="#0A2E2A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
      <div><div class="brand">Cyber<span>Testify</span></div><div class="rtype">Otonom AI Red Team — Bulgu Raporu</div></div>
    </div>
    <div class="cover-body">
      <div class="cover-target-wrap">
        <div class="cover-target-k">HEDEF ALAN ADI</div>
        <div class="cover-target">${esc(r.meta.target)}</div>
      </div>
      <div class="cover-badges">
        <span class="cbadge cbadge-lvl">${esc(r.meta.level)} · Deneysel</span>
        <span class="cbadge cbadge-risk" style="background:${rc}">Genel risk: ${esc(RISK_LABEL[r.overallRisk] ?? r.overallRisk)}</span>
        <span class="cbadge cbadge-env">Ortam: ${esc(r.meta.environment)}</span>
      </div>
      <div class="cover-info">
        <div><span class="k">Rapor No</span><span class="v">${esc(reportNo)}</span></div>
        <div><span class="k">Tarih</span><span class="v">${esc(String(r.meta.generatedAt).slice(0, 10))}</span></div>
      </div>
      <div class="cover-counts">
        <div class="cc"><b style="color:#15803d">${r.counts.kanitli}</b><span>Kanıtlı</span></div>
        <div class="cc"><b style="color:#a16207">${r.counts.belirsiz}</b><span>İnceleme</span></div>
        <div class="cc"><b style="color:#64748b">${r.eliminated}</b><span>Elenen</span></div>
        ${admin ? `<div class="cc"><b style="color:#334155">${r.counts.artifacts}</b><span>Ham artefakt</span></div>` : ''}
      </div>
    </div>
    <div class="cover-warn">⚠ <b>DENEYSEL · DETERMİNİSTİK DEĞİL · resmi denetim/sertifikasyon DEĞİL.</b> Her "kanıtlı" bulgu saklanan ham kanıta bağlıdır.</div>
  </section>

  <!-- (P0-6) İÇİNDEKİLER — statik şablon, 8 bölümün sırasını birebir yansıtır; tıklanır bağlantı (PDF içi).
       Sayfa no YAZILMAZ: Chromium target-counter'ı desteklemez, YANLIŞ sayfa no "uydurma sayı yasağı"na aykırı olur. -->
  <section class="toc-page">
    <h2>İçindekiler</h2>
    <div class="toc-row"><a href="#s-ozet"><span class="tnum">1</span>Yönetici Özeti</a></div>
    <div class="toc-row"><a href="#s-kanitli"><span class="tnum">2</span>Kanıtlı Bulgular</a></div>
    <div class="toc-row"><a href="#s-belirsiz"><span class="tnum">3</span>İnceleme Gerektiren — Belirsiz</a></div>
    <div class="toc-row"><a href="#s-elenen"><span class="tnum">4</span>Elenen — Hayalet</a></div>
    <div class="toc-row"><a href="#s-metodoloji"><span class="tnum">5</span>Metodoloji ve Kapsam</a></div>
    <div class="toc-row"><a href="#s-poz"><span class="tnum">6</span>Pozitif Güvence — Denenen Kontroller</a></div>
    <div class="toc-row"><a href="#s-sinir"><span class="tnum">7</span>Sınırlılıklar</a></div>
    <div class="toc-row"><a href="#s-ek"><span class="tnum">8</span>Ek: Artefakt Özeti</a></div>
  </section>

  ${r.stoppedReason ? `<div class="disc" style="background:#fef2f2;border-color:#f87171;border-left-color:#dc2626;color:#7f1d1d">⏱ KOŞU ZORLA DURDURULDU: ${esc(r.stoppedReason)}</div>` : ''}
  ${r.healthNote ? `<div class="disc" style="background:#fffbeb;border-color:#f59e0b;border-left-color:#d97706;color:#78350f">⚠ HEDEF YANIT VERMEDİ: ${esc(r.healthNote)}</div>` : ''}

  <h2 id="s-ozet">Yönetici Özeti</h2>
  <div class="exec">
    <p style="margin:0 0 8px"><b>Ne test edildi:</b> Otonom bir yapay-zekâ ajanı (PentAGI), <b>${esc(r.meta.target)}</b> hedefini <b>${esc(r.meta.level)}</b> profilinde, izole ${admin ? 've cap-sınırlı ' : ''}bir ortamda gerçek saldırı teknikleriyle sınadı.</p>
    <p style="margin:0 0 8px"><b>Ne denendi (sayılarla):</b> ${esc(triedSentence)}. Kanıt-bağlama modeli: her iddia ajanın SÖZÜNE değil saklanan HAM kanıta (gerçek istek/yanıt, terminal çıktısı) bağlanır — deterministik imza varsa <b>kanıtlı</b>, kanıt var imza yoksa <b>inceleme gerektiren</b>, hiç izi yoksa (ya da hedef-dışı) <b>elenir</b>.</p>
    <p style="margin:0 0 8px"><b>Ne bulunamadı / kapsam:</b> Bu koşu ${esc(r.meta.level)} profili${admin ? ' ve cap-sınırlı süre/bütçeyle' : ' kapsamıyla'} yürütüldü; kapsam yalnızca pinlenen hedeftir (${esc(r.meta.target)}). Kimlikli/derin testler ve S1 dışı teknik aileleri bu koşunun dışındadır — "kanıtlı bulgu yok", "zafiyet yok" anlamına gelmez.</p>
    <p style="margin:0 0 8px"><b>Genel duruş:</b> ${esc(posture)}</p>
    <div class="notbox">
      <b>Bu rapor ne DEĞİLDİR?</b>
      <ul>
        <li>Resmi bir sızma testi (pentest) sertifikası ya da uygunluk denetimi (ör. ASV/QSA) <b>değildir</b>.</li>
        <li>Kimlikli/oturum-sonrası derin testleri <b>içermez</b> — bu koşu ${esc(r.meta.level)} kapsamıyla sınırlıdır.</li>
        <li>Deterministik <b>değildir</b>: aynı hedefte tekrar çalıştırıldığında farklı sonuç verebilir.</li>
      </ul>
    </div>
    <p style="margin:8px 0 0;background:#ecfdf5;border:1px solid #a7f3d0;border-radius:6px;padding:8px 12px"><b>Önerilen sonraki adım:</b> ${esc(nextStep)}</p>
    <div class="sum">
      <div><span class="risk">Genel risk: ${esc(RISK_LABEL[r.overallRisk] ?? r.overallRisk)}</span></div>
      <div><b style="color:#15803d">${r.counts.kanitli}</b>Kanıtlı</div>
      <div><b style="color:#a16207">${r.counts.belirsiz}</b>İnceleme gerektiren</div>
      <div><b style="color:#64748b">${r.eliminated}</b>Elenen (hayalet)</div>
      ${admin ? `<div><b style="color:#334155">${r.counts.artifacts}</b>Ham artefakt</div>` : ''}
    </div>
  </div>

  <h2 id="s-kanitli">Kanıtlı Bulgular (${r.proven.length})</h2>
  ${r.proven.length ? r.proven.map((f) => card(f, false)).join('') : '<p class="empty">Kanıtlı bulgu yok — bu koşuda ham kanıta bağlanan doğrulanmış bir zafiyet üretilmedi.</p>'}

  <h2 id="s-belirsiz">İnceleme Gerektiren — Belirsiz (${r.needsReview.length})</h2>
  <p style="font-size:12px;color:#64748b;margin:0 0 10px">Ham artefaktı olan ama kesin deterministik imzası olmayan iddialar. Silinmemiştir; <b>insan doğrulaması</b> önerilir. Genel riski ETKİLEMEZ.</p>
  ${r.needsReview.length ? r.needsReview.map((f) => card(f, true)).join('') : '<p class="empty">İnceleme gerektiren bulgu yok.</p>'}

  <h2 id="s-elenen">Elenen — Hayalet (${r.eliminated})</h2>
  <p style="font-size:12px;color:#64748b;margin:0">Ajanın iddia ettiği ama <b>hiçbir ham kanıtı bulunmayan</b> ya da <b>hedef-dışı host</b> referanslayan bulgular elendi ve rapora ALINMADI (detay verilmez — kanıtı yoktur). Bu, yanlış-pozitifi ve ajanın eğitim-bilgisi sızıntısını önleyen kasıtlı bir dürüstlük kuralıdır.</p>

  <h2 id="s-metodoloji">Metodoloji ve Kapsam</h2>
  <table class="scope"><tbody>
    <tr><th>Motor</th><td>Otonom PentAGI ajanı — gerçek saldırı teknikleri (simülasyon değil)</td></tr>
    <tr><th>Kanıt-bağlama</th><td>Üç katman: kanıtlı (deterministik imza) / belirsiz (insan-inceleme) / hayalet (elenir)</td></tr>
    <tr><th>İzolasyon</th><td>${admin
      ? 'Efemer izole droplet; egress yalnız yetkili hedef + LLM; CyberTestify/dış/metadata engelli (ampirik doğrulandı)'
      : 'Test, her koşuda tek-kullanımlık ve izole bir ortamda yürütülür; dış erişim yalnızca yetkilendirilmiş hedefe sınırlıdır.'}</td></tr>
    <tr><th>Provenance</th><td>Yalnız pinlenen hedefe (${esc(r.meta.target)}) ait bulgular; hedef-dışı host referansları elenir</td></tr>
    ${admin ? `<tr><th>Bütçe</th><td>Sert cap (süre/kapsam); aşımda otomatik güvenli durdurma${r.meta.costUsd != null ? ` — bu koşu ~$${Number(r.meta.costUsd).toFixed(4)}` : ''}</td></tr>` : ''}
    <tr><th>Yetki</th><td>Sahiplik/yetki beyanı + risk onayı ile; ${esc(r.meta.environment)} ortamı</td></tr>
  </tbody></table>

  <h2 id="s-poz">Pozitif Güvence — Denenen ve Kanıt Üretmeyen Kontroller</h2>
  <p style="font-size:12px;color:#64748b;margin:0 0 8px">Aşağıdaki sayılar, ajanın hedefe karşı gerçekten yürüttüğü ve saklanan ham artefaktlarla ölçülen etkileşimlerdir (uydurma değil). Bir uç-noktanın burada yer alması, denendiği ama <b>bu koşuda</b> kanıtlı bir zafiyet imzası üretmediği anlamına gelir.</p>
  <div class="assur">
    <div class="ac"><b>${t.httpRequests ?? 0}</b><span>HTTP isteği</span></div>
    <div class="ac"><b>${t.endpointCount ?? (t.endpoints?.length ?? 0)}</b><span>Denenen uç-nokta</span></div>
    ${admin ? `<div class="ac"><b>${t.terminalArtifacts ?? r.counts.artifacts}</b><span>Terminal artefaktı</span></div>` : ''}
    <div class="ac"><b>${t.families?.length ?? 0}</b><span>Teknik ailesi</span></div>
  </div>
  ${t.endpoints?.length ? `<div style="font-size:12px;color:#475569;margin-top:6px"><b>Denenen uç-noktalar:</b></div><div class="chips">${t.endpoints.map((e) => `<code>${esc(e)}</code>`).join('')}</div>` : ''}
  ${t.families?.length ? `<div style="font-size:12px;color:#475569;margin-top:2px"><b>Denenen teknik aileleri:</b></div><div class="chips">${t.families.map((f) => `<code>${esc(f)}</code>`).join('')}</div>` : ''}

  <h2 id="s-sinir">Sınırlılıklar</h2>
  <ul class="lim">
    <li><b>Deneyseldir ve deterministik değildir:</b> aynı hedefte tekrar çalıştırıldığında farklı sonuç verebilir; resmi bir denetim/sertifikasyon (ASV/QSA) yerine geçmez.</li>
    <li><b>Sınırlı kapsam:</b> koşu, ${admin ? 'süre, token ve maliyet capleriyle sınırlıdır. Cap dolduğunda' : 'tanımlı bir kapsamla sınırlıdır; kapsam dolduğunda'} tarama, kapsamı tam bitirmeden durabilir.</li>
    <li><b>Yalnız gözlemlenen kanıt:</b> "kanıtlı bulgu yok" ifadesi "hedef güvenli" anlamına gelmez — yalnız bu koşuda ham kanıta bağlanan bir zafiyet üretilmediğini belirtir.</li>
    <li><b>${esc(r.meta.level)} profili:</b> yalnızca bu profilin teknik aileleri denenmiştir; kimlikli/oturumlu derin testler ve S1 dışı vektörler kapsam dışıdır.</li>
    <li><b>İnsan doğrulaması:</b> "inceleme gerektiren" bulgular otomatik teyit edilmemiştir; üretim kararları öncesi bir uzmana doğrulatılmalıdır.</li>
  </ul>

  <h2 id="s-ek">Ek: Artefakt Özeti</h2>
  <table class="scope"><tbody>
    ${admin ? `<tr><th>Ham artefakt (toplam)</th><td>${r.counts.artifacts}</td></tr>` : ''}
    <tr><th>HTTP isteği</th><td>${t.httpRequests ?? '—'}</td></tr>
    ${admin ? `<tr><th>Terminal artefaktı</th><td>${t.terminalArtifacts ?? '—'}</td></tr>` : ''}
    <tr><th>Kanıtlı / Belirsiz / Elenen</th><td>${r.counts.kanitli} / ${r.counts.belirsiz} / ${r.eliminated}</td></tr>
    ${admin && r.filteredMeta != null ? `<tr><th>Filtrelenen plan/meta iddia</th><td>${r.filteredMeta} <span class="ref">(subtask/plan/arama — kanıt değil, elendi)</span></td></tr>` : ''}
    ${admin && r.eliminatedReasons && Object.keys(r.eliminatedReasons).length ? `<tr><th>Eleme kırılımı</th><td>${Object.entries(r.eliminatedReasons).map(([k, v]) => `${esc(k)}: ${v}`).join(' · ')}</td></tr>` : ''}
    ${admin && r.meta.costUsd != null ? `<tr><th>Gerçek maliyet</th><td>~$${Number(r.meta.costUsd).toFixed(4)} <span class="ref">(msgchains token muhasebesinden)</span></td></tr>` : ''}
    ${admin && r.meta.llmCalls != null ? `<tr><th>LLM çağrısı</th><td>${r.meta.llmCalls}</td></tr>` : ''}
    ${admin && r.meta.agentSec != null ? `<tr><th>Ajan süresi</th><td>${r.meta.agentSec}s <span class="ref">(yalnız otonom ajanın çalıştığı süre — cap bu süreyi sınırlar)</span></td></tr>` : ''}
    ${admin && r.meta.elapsedSec != null ? `<tr><th>Toplam süre</th><td>${r.meta.elapsedSec}s <span class="ref">(uçtan uca: hazırlık + kurulum + ajan + bağlama + yıkım${r.meta.agentSec != null ? ` — fark ~${Math.max(0, r.meta.elapsedSec - r.meta.agentSec)}s altyapı fazlarıdır, ajan cap’i değil` : ''})</span></td></tr>` : ''}
  </tbody></table>

  <p style="margin-top:20px;font-size:11px;color:#94a3b8;border-top:1px solid #e2e8f0;padding-top:10px">Bu rapor deneysel otonom red-team katmanı tarafından üretilmiştir ve deterministik değildir; resmi bir güvenlik denetimi ya da uygunluk belgesi yerine geçmez. Kanıtlı bulgular ham kanıta bağlıdır; belirsiz bulgular insan doğrulaması bekler.</p>
</body></html>`;
}
