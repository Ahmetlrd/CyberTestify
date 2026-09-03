/**
 * (LINKEDIN CAROUSEL) Slayt tanimindan LinkedIn'in NATIF dokuman gonderisi olarak render ettigi
 * KARE PDF uretir + tek-gorsel gonderiler icin PNG uretir.
 *
 * NEDEN KARE: LinkedIn dokuman carousel'i akista 1:1 (veya 4:5) oranda gosterir. A4 dikey sayfa
 * kucucuk ve okunmaz gorunur; bu yuzden sayfa boyutu 1080x1080 pikseldir.
 *
 * Marka: koyu teal #123F3A zemin + amber #F5A623 aksan (rapor kapagiyla AYNI dil).
 * Puppeteer/Chromium zaten raporlama icin kurulu — yeni bagimlilik YOK.
 */
import puppeteer from 'puppeteer-core';

const CHROMIUM_PATH = process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/chromium-browser';
const SIZE = 1080;

export type Slide = {
  /** Ust kose kucuk etiket — ör. "01 / 08" veya "CHECKLIST" */
  kicker?: string;
  title: string;
  /** Serbest paragraf */
  body?: string;
  /** Madde listesi (paragraf yerine veya sonrasinda) */
  bullets?: string[];
  /** Kapak/kapanis slaytlari icin farkli zemin */
  variant?: 'cover' | 'content' | 'cta';
};

const esc = (s: string): string =>
  String(s ?? '').replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]!));

/** Basit **kalin** isaretlemesi — slayt metninde vurgu icin. */
const md = (s: string): string => esc(s).replace(/\*\*(.+?)\*\*/g, '<b>$1</b>');

function slideHtml(s: Slide, idx: number, total: number): string {
  const v = s.variant ?? 'content';
  const bullets = s.bullets?.length
    ? `<ul>${s.bullets.map((b) => `<li>${md(b)}</li>`).join('')}</ul>`
    : '';
  const body = s.body ? `<p class="body">${md(s.body)}</p>` : '';
  return `<section class="slide ${v}">
    <div class="top">
      <div class="brand">Cyber<span>Testify</span></div>
      ${v === 'content' ? `<div class="page">${idx} / ${total}</div>` : ''}
    </div>
    <div class="mid">
      ${s.kicker ? `<div class="kicker">${esc(s.kicker)}</div>` : ''}
      <h1 class="${v === 'cover' ? 'big' : ''}">${md(s.title)}</h1>
      ${body}${bullets}
    </div>
    <div class="bot">${v === 'cover' ? 'Swipe →' : v === 'cta' ? 'cybertestify.com' : ''}</div>
  </section>`;
}

function documentHtml(slides: Slide[]): string {
  const total = slides.length;
  return `<!doctype html><html><head><meta charset="utf-8"><style>
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{background:#fff}
  body{font-family:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .slide{width:${SIZE}px;height:${SIZE}px;padding:78px 84px;display:flex;flex-direction:column;
         justify-content:space-between;page-break-after:always;overflow:hidden;position:relative}
  .slide:last-child{page-break-after:auto}
  .content{background:#FFFFFF;color:#12231F}
  .cover,.cta{background:linear-gradient(150deg,#123F3A 0%,#0A2E2A 100%);color:#EEF5F3}
  .top{display:flex;justify-content:space-between;align-items:center}
  .brand{font-size:27px;font-weight:800;letter-spacing:.2px}
  .content .brand{color:#123F3A} .cover .brand,.cta .brand{color:#fff}
  .brand span{color:#F5A623}
  .page{font-size:22px;font-weight:700;color:#8FA8A2}
  .mid{flex:1;display:flex;flex-direction:column;justify-content:center;gap:26px}
  .kicker{font-size:21px;font-weight:800;letter-spacing:2.4px;text-transform:uppercase;color:#F5A623}
  h1{font-size:60px;line-height:1.12;font-weight:800;letter-spacing:-.6px;max-width:19ch}
  h1.big{font-size:78px;line-height:1.06;max-width:16ch}
  .content h1{color:#0E2E2A}
  .body{font-size:33px;line-height:1.46;max-width:26ch}
  .content .body{color:#3A4A47} .cover .body,.cta .body{color:#BFD8D2;max-width:24ch}
  ul{list-style:none;display:flex;flex-direction:column;gap:19px}
  li{font-size:31px;line-height:1.38;padding-left:44px;position:relative;max-width:25ch}
  .content li{color:#243A36} .cover li,.cta li{color:#D6E7E2}
  li::before{content:"";position:absolute;left:0;top:14px;width:22px;height:5px;border-radius:3px;background:#F5A623}
  .bot{font-size:23px;font-weight:700;color:#F5A623;min-height:30px}
  /* Alt amber serit — her sayfada marka tutarliligi */
  .slide::after{content:"";position:absolute;left:0;right:0;bottom:0;height:9px;background:#F5A623}
  .content::after{background:#123F3A}
  </style></head><body>${slides.map((s, i) => slideHtml(s, i + 1, total)).join('')}</body></html>`;
}

async function withPage<T>(fn: (page: import('puppeteer-core').Page) => Promise<T>): Promise<T> {
  const browser = await puppeteer.launch({
    executablePath: CHROMIUM_PATH,
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--font-render-hinting=none'],
  });
  try {
    const page = await browser.newPage();
    await page.setViewport({ width: SIZE, height: SIZE, deviceScaleFactor: 2 });
    return await fn(page);
  } finally {
    await browser.close();
  }
}

/** Slaytlardan 1080x1080 KARE sayfali PDF (LinkedIn natif dokuman carousel'i). */
export async function renderCarouselPdf(slides: Slide[]): Promise<Buffer> {
  if (!slides.length) throw new Error('En az bir slayt gerekir.');
  return withPage(async (page) => {
    await page.setContent(documentHtml(slides), { waitUntil: 'load' });
    const pdf = await page.pdf({
      width: `${SIZE}px`, height: `${SIZE}px`,
      printBackground: true, pageRanges: `1-${slides.length}`,
      margin: { top: '0', bottom: '0', left: '0', right: '0' },
    });
    return Buffer.from(pdf);
  });
}

/** Tek-gorsel gonderiler icin 1080x1080 PNG (ayni tasarim dili). */
export async function renderSlidePng(slide: Slide): Promise<Buffer> {
  return withPage(async (page) => {
    await page.setContent(documentHtml([slide]), { waitUntil: 'load' });
    const el = await page.$('.slide');
    if (!el) throw new Error('Slayt render edilemedi.');
    const shot = await el.screenshot({ type: 'png' });
    return Buffer.from(shot);
  });
}
