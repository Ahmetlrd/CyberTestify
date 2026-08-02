import MarkdownIt from 'markdown-it';
import puppeteer from 'puppeteer-core';

/**
 * (3) Rapor PDF uretimi — SAF FORMATLAMA/RENDER. Ek LLM cagrisi YOK, ek Anthropic
 * maliyeti YOK: icerik (bulgular + varsa fix onerileri) zaten uretilmis Markdown;
 * burada yalnizca marka kimligine uygun, sunulabilir bir PDF'e donusturuluyor.
 *
 * Motor: markdown-it (MD->HTML) + puppeteer-core ile headless Chromium (HTML->PDF).
 * Chromium sistemden gelir (PUPPETEER_EXECUTABLE_PATH; Docker'da apk chromium).
 *
 * Marka (frontend/tailwind.config.ts brief): derin teal #123F3A + amber CTA #F5A623.
 */

const md = new MarkdownIt({
  html: false, // GUVENLIK: ajan uretimi icerikte ham HTML'e izin verme (PDF injection)
  linkify: true,
  breaks: false,
});

export interface ReportPdfMeta {
  hostname: string;
  packageName: string;
  createdAt: Date;
  locale: 'tr' | 'en';
}

export interface ReportPdfOptions {
  fixMarkdown?: string | null; // unlock edilmisse fix onerileri Markdown'i
  fixLocked?: boolean; // fix onerisi VAR ama satin alinmamis (kilitli goster)
}

const CHROMIUM_PATH = process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/chromium-browser';

const L = {
  tr: {
    brandTagline: 'Otomatik Güvenlik Tarama Raporu',
    target: 'Hedef', pkg: 'Paket', date: 'Tarih',
    fixTitle: 'AI Çözüm Önerileri',
    fixLocked: 'Bu bölüm kilitli — "AI Çözüm Önerileri" eklentisi satın alınınca rapora eklenir.',
    footerLegal: 'Yapay zeka üretimi pasif tarama raporu — resmi denetim/sertifikasyon değildir. Gizlidir.',
    page: 'Sayfa',
  },
  en: {
    brandTagline: 'Automated Security Scan Report',
    target: 'Target', pkg: 'Package', date: 'Date',
    fixTitle: 'AI Fix Suggestions',
    fixLocked: 'This section is locked — it is added once the "AI Fix Suggestions" add-on is purchased.',
    footerLegal: 'AI-generated passive scan report — not an official audit/certification. Confidential.',
    page: 'Page',
  },
} as const;

// CyberTestify kalkan logosu (inline SVG — dis kaynak yok).
const LOGO_SVG = `
<svg width="34" height="34" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M12 2L4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3z" fill="#F5A623"/>
  <path d="M9.2 12.2l1.9 1.9 3.9-4.1" stroke="#123F3A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
</svg>`.trim();

function escapeHtml(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] as string));
}

function buildHtml(bodyMd: string, meta: ReportPdfMeta, opts: ReportPdfOptions): string {
  const t = L[meta.locale];
  const dateStr = meta.createdAt.toLocaleDateString(meta.locale === 'tr' ? 'tr-TR' : 'en-GB', {
    year: 'numeric', month: 'long', day: 'numeric',
  });

  // Ust banner zaten Hedef/Paket/Tarih'i gosteriyor; markdown'in kendi baslik+meta
  // blogunu (ilk '---' cizgisine kadar) at ki tekrar olmasin. Yalniz H1 ile basliyorsa.
  let effectiveMd = bodyMd;
  if (effectiveMd.startsWith('# ')) {
    const hr = effectiveMd.indexOf('\n---\n');
    if (hr !== -1 && hr < 500) effectiveMd = effectiveMd.slice(hr + 5);
  }

  let bodyHtml = md.render(effectiveMd);

  // Fix onerileri bolumu (unlock ise ekle; kilitliyse kilit notu; hic yoksa ekleme).
  if (opts.fixMarkdown && opts.fixMarkdown.trim()) {
    bodyHtml += `<div class="fix-section"><h2>${escapeHtml(t.fixTitle)}</h2>${md.render(opts.fixMarkdown)}</div>`;
  } else if (opts.fixLocked) {
    bodyHtml += `<div class="fix-locked"><h2>🔒 ${escapeHtml(t.fixTitle)}</h2><p>${escapeHtml(t.fixLocked)}</p></div>`;
  }

  return `<!doctype html><html lang="${meta.locale}"><head><meta charset="utf-8">
<style>
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    font-family: -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif;
    color: #1b2b28; font-size: 12px; line-height: 1.55; -webkit-print-color-adjust: exact; print-color-adjust: exact;
  }
  .cover-band {
    background: linear-gradient(135deg, #123F3A 0%, #0A2E2A 100%); color: #EEF5F3;
    padding: 22px 34px; display: flex; align-items: center; gap: 14px;
  }
  .cover-band .brand { font-size: 20px; font-weight: 700; letter-spacing: .3px; color: #ffffff; }
  .cover-band .brand span { color: #F5A623; }
  .cover-band .tagline { font-size: 11px; color: #9Fc4bc; margin-top: 2px; }
  .meta {
    display: flex; gap: 26px; padding: 14px 34px; background: #EEF5F3;
    border-bottom: 3px solid #F5A623; font-size: 11px;
  }
  .meta .k { color: #5FA396; text-transform: uppercase; letter-spacing: .5px; font-size: 9px; font-weight: 700; }
  .meta .v { color: #123F3A; font-weight: 600; font-size: 12.5px; }
  .content { padding: 20px 34px 30px; }
  h1 { color: #123F3A; font-size: 20px; margin: 6px 0 14px; border-bottom: 2px solid #DCEAE6; padding-bottom: 8px; }
  h2 { color: #14514A; font-size: 15px; margin: 20px 0 8px; }
  h3 { color: #1C6B60; font-size: 13px; margin: 14px 0 6px; }
  p { margin: 6px 0; }
  a { color: #14514A; }
  code { background: #EEF5F3; padding: 1px 5px; border-radius: 3px; font-size: 11px; }
  pre { background: #0A2E2A; color: #DCEAE6; padding: 12px 14px; border-radius: 6px; overflow-x: auto; font-size: 10.5px; }
  pre code { background: none; color: inherit; padding: 0; }
  ul, ol { margin: 6px 0 6px 4px; padding-left: 20px; }
  li { margin: 3px 0; }
  table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 11px; }
  th { background: #123F3A; color: #fff; text-align: left; padding: 8px 10px; font-weight: 600; }
  td { padding: 7px 10px; border-bottom: 1px solid #DCEAE6; vertical-align: top; }
  tr:nth-child(even) td { background: #F6FAF8; }
  blockquote { margin: 10px 0; padding: 8px 14px; background: #FDECC8; border-left: 4px solid #F5A623; border-radius: 0 4px 4px 0; }
  hr { border: none; border-top: 1px solid #DCEAE6; margin: 18px 0; }
  /* Siddet (severity) renk kodlari — inline script <td>'lere sinif ekler */
  td.sev-critical { border-left: 4px solid #B3261E; }
  td.sev-critical .sev-badge { background: #B3261E; }
  td.sev-high { border-left: 4px solid #D64545; }
  td.sev-high .sev-badge { background: #D64545; }
  td.sev-medium { border-left: 4px solid #F5A623; }
  td.sev-medium .sev-badge { background: #E0940E; }
  td.sev-low { border-left: 4px solid #9AA0A6; }
  td.sev-low .sev-badge { background: #9AA0A6; }
  td.sev-info { border-left: 4px solid #5FA396; }
  td.sev-info .sev-badge { background: #5FA396; }
  .sev-badge { color: #fff; padding: 1px 7px; border-radius: 10px; font-size: 9.5px; font-weight: 700; white-space: nowrap; }
  .fix-section { margin-top: 22px; padding-top: 4px; border-top: 2px solid #F5A623; }
  .fix-section h2 { color: #E0940E; }
  .fix-locked { margin-top: 22px; padding: 14px; background: #EEF5F3; border: 1px dashed #5FA396; border-radius: 6px; color: #14514A; }
  .fix-locked h2 { color: #5FA396; margin: 0 0 4px; font-size: 14px; }
</style></head>
<body>
  <div class="cover-band">
    ${LOGO_SVG}
    <div>
      <div class="brand">Cyber<span>Testify</span></div>
      <div class="tagline">${escapeHtml(t.brandTagline)}</div>
    </div>
  </div>
  <div class="meta">
    <div><div class="k">${escapeHtml(t.target)}</div><div class="v">${escapeHtml(meta.hostname)}</div></div>
    <div><div class="k">${escapeHtml(t.pkg)}</div><div class="v">${escapeHtml(meta.packageName)}</div></div>
    <div><div class="k">${escapeHtml(t.date)}</div><div class="v">${escapeHtml(dateStr)}</div></div>
  </div>
  <div class="content">${bodyHtml}</div>
  <script>
    // Siddet kelimelerine gore tablo hucrelerini renklendir (TR+EN, buyuk/kucuk duyarsiz).
    (function () {
      var map = [
        { cls: 'sev-critical', re: /\\b(kritik|critical)\\b/i },
        { cls: 'sev-high', re: /\\b(y[uü]ksek|high)\\b/i },
        { cls: 'sev-medium', re: /\\b(orta|medium)\\b/i },
        { cls: 'sev-low', re: /\\b(d[uü][sş][uü]k|low)\\b/i },
        { cls: 'sev-info', re: /\\b(bilgi|info|informational)\\b/i },
      ];
      document.querySelectorAll('td').forEach(function (td) {
        var txt = (td.textContent || '').trim();
        if (txt.length > 24) return; // yalniz kisa "durum/siddet" hucreleri
        // Turkce buyuk-I sorunu: "KRİTİK".toLowerCase() != "kritik"; tr locale ile normalize.
        var norm = txt.toLocaleLowerCase('tr');
        for (var i = 0; i < map.length; i++) {
          if (map[i].re.test(norm)) {
            td.classList.add(map[i].cls);
            td.innerHTML = '<span class="sev-badge">' + txt + '</span>';
            break;
          }
        }
      });
    })();
  </script>
</body></html>`;
}

/**
 * Markdown rapor + (opsiyonel) fix onerilerini markali PDF Buffer'ina cevirir.
 * Ek LLM cagrisi yapmaz. Chromium'u her cagride acip kapatir (rapor seyrek uretilir).
 */
export async function renderReportPdf(
  bodyMarkdown: string,
  meta: ReportPdfMeta,
  opts: ReportPdfOptions = {},
): Promise<Buffer> {
  const html = buildHtml(bodyMarkdown, meta, opts);
  const t = L[meta.locale];

  const browser = await puppeteer.launch({
    executablePath: CHROMIUM_PATH,
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--font-render-hinting=none'],
  });
  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'load' });
    const pdf = await page.pdf({
      format: 'A4',
      printBackground: true,
      margin: { top: '14mm', bottom: '18mm', left: '0mm', right: '0mm' },
      displayHeaderFooter: true,
      headerTemplate: '<div></div>',
      footerTemplate: `
        <div style="width:100%; font-size:8px; color:#5FA396; padding:0 12mm;
                    display:flex; justify-content:space-between; align-items:center;">
          <span style="max-width:78%;">${escapeHtml(t.footerLegal)}</span>
          <span>${escapeHtml(t.page)} <span class="pageNumber"></span>/<span class="totalPages"></span></span>
        </div>`,
    });
    return Buffer.from(pdf);
  } finally {
    await browser.close();
  }
}
