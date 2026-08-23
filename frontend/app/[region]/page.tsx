import Link from 'next/link';
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { AutonomousSection } from '../../components/landing/AutonomousSection';
import { InstantScan } from '../../components/landing/InstantScan';
import { TrustSection } from '../../components/landing/TrustSection';
import { JsonLd } from '../../components/JsonLd';
import { VISIBLE_REGION_CODES, isRegionCode, getRegion, type RegionConfig } from '../../config/regions';
import { getDict, type Dict } from '../../config/i18n';

const SITE = 'https://cybertestify.com';

export function generateStaticParams() {
  return VISIBLE_REGION_CODES.map((region) => ({ region }));
}

// (SEO) Ana sayfa — bölgeye göre BENZERSİZ başlık/açıklama + canonical + OG (dürüst dil; "otonom pentest" YOK).
export function generateMetadata({ params }: { params: { region: string } }): Metadata {
  const region = isRegionCode(params.region) ? getRegion(params.region) : getRegion('tr');
  const tr = region.lang === 'tr';
  // (SEO) Başlık 50-60, açıklama 150-160 karakterde tutulur (Google kırpması olmasın) — dürüst
  // "resmi pentest değil" ibaresi korunur.
  const title = tr
    ? 'CyberTestify — Dakikalar İçinde AI Güvenlik Taraması'
    : 'CyberTestify — AI-Assisted Website Security Scan';
  const description = tr
    ? 'Yapay zekâ destekli otomatik web güvenlik ön değerlendirmesi (resmi pentest değil). Alan adınızı doğrulayın, paketinizi seçin, şifreli raporunuzu alın.'
    : 'AI-assisted automated website security pre-assessment (not a formal pentest). Verify your domain, pick a package, get your encrypted report.';
  const url = `${SITE}/${region.code}`;
  return {
    title,
    description,
    alternates: { canonical: url },
    openGraph: { type: 'website', siteName: 'CyberTestify', url, title, description, locale: tr ? 'tr_TR' : 'en_US' },
    twitter: { card: 'summary_large_image', title, description },
  };
}

// (SEO/AEO) Sık sorulan sorular — Google zengin sonuç + AI asistan kaynağı. DÜRÜST yanıtlar.
const FAQ_TR = [
  { q: 'CyberTestify tam olarak ne yapar?', a: 'Web sitenize yapay zekâ destekli, otomatik bir güvenlik ön-değerlendirmesi yapar: deterministik güvenlik kontrolleri çalıştırır ve bulgular için yapay zekâ destekli çözüm önerileri üretir. Resmî bir sızma testi/denetim yerine geçmez.' },
  { q: 'Raporu kim görebilir?', a: 'Raporunuz uçtan uca şifrelenir ve yalnızca size özel, tek kullanımlık bir kodla açılır. Başka kimse erişemez.' },
  { q: 'Hangi paket bana uygun?', a: 'Hızlı bir ön izleme için Basit Tarama; dış yüzey, keşif, uyum ya da kimlik-doğrulamalı derin kontroller için ilgili kombine paketleri seçebilirsiniz. Her paketin kapsamı ve sabit fiyatı paketler sayfasında açıkça yazılıdır.' },
  { q: 'Verilerim güvende mi?', a: 'Taramalar yalnızca sahipliğini DNS ile doğruladığınız alan adına erişebilir (kapsam kilidi). Karşılaşılan kişisel veriler yapay zekâya ulaşmadan önce otomatik maskelenir; işlemler KVKK’ya uygun yürütülür.' },
  { q: 'Sonuç ne kadar sürede hazır olur?', a: 'Deterministik paketler genellikle saniyeler–dakikalar içinde tamamlanır; kimlik-doğrulamalı/kapsamlı paketler daha uzun sürebilir. Süre pakete ve hedefin yapısına göre değişir.' },
  { q: 'Bu resmî bir sızma testi mi?', a: 'Hayır. CyberTestify bir güvenlik ön-değerlendirme hizmetidir; resmî bir sızma testi ya da uyum denetimi (ör. ASV/QSA) yerine geçmez ve bir sertifikasyon sağlamaz.' },
];
const FAQ_EN = [
  { q: 'What exactly does CyberTestify do?', a: 'It runs an AI-assisted, automated security pre-assessment of your website: deterministic security checks plus AI-assisted remediation suggestions for findings. It is not a substitute for a formal pentest/audit.' },
  { q: 'Who can see the report?', a: 'Your report is end-to-end encrypted and opened only with a one-time code unique to you. No one else can access it.' },
  { q: 'Which package is right for me?', a: 'Pick Basic Scan for a quick preview, or the relevant bundle for external surface, discovery, compliance readiness or authenticated deep checks. Each package’s scope and fixed price are stated clearly on the pricing page.' },
  { q: 'Is my data safe?', a: 'Scans can only reach the domain you verified via DNS (scope lock). Personal data encountered is automatically masked before it reaches the AI; processing follows applicable data-protection rules.' },
  { q: 'How long does it take?', a: 'Deterministic packages usually finish in seconds to minutes; authenticated/comprehensive packages can take longer. Time varies by package and target.' },
  { q: 'Is this a formal penetration test?', a: 'No. CyberTestify is a security pre-assessment service; it is not a substitute for a formal penetration test or compliance audit and does not provide certification.' },
];

// (LANSMAN KAMPANYASI) AI Çözüm Önerileri kısa süreliğine ÜCRETSİZ. Kapatmak için
// NEXT_PUBLIC_AI_FIX_FREE_CAMPAIGN=false (env tanımsızsa varsayılan: AÇIK/gösterilir).
const AI_FIX_FREE_CAMPAIGN = process.env.NEXT_PUBLIC_AI_FIX_FREE_CAMPAIGN !== 'false';

function CampaignBanner({ region }: { region: RegionConfig }) {
  if (!AI_FIX_FREE_CAMPAIGN) return null;
  const tr = region.lang === 'tr';
  return (
    <Link
      href={`/${region.code}/packages`}
      /* Sticky: global Nav (sticky top-0, h-16, z-40) HEMEN ALTINA sabitlenir (top-16, z-30) →
         aşağı kaydırınca kampanya şeridi kaybolmaz. */
      className="group sticky top-16 z-30 block bg-gradient-to-r from-amber-400 via-orange-500 to-amber-500 text-white shadow-sm"
    >
      <div className="container-page flex flex-wrap items-center justify-center gap-x-3 gap-y-1 py-2.5 text-center text-sm font-semibold">
        <span className="rounded-pill bg-white/20 px-2.5 py-0.5 text-xs font-extrabold tracking-wide">
          {tr ? 'KAMPANYAYA ÖZEL' : 'LAUNCH OFFER'}
        </span>
        <span>
          {tr ? (
            <>
              Kısa süreliğine <strong>tüm raporlarda AI Çözüm Önerileri ÜCRETSİZ</strong>
            </>
          ) : (
            <>
              For a limited time <strong>AI Fix Suggestions are FREE</strong> on every report
            </>
          )}
        </span>
        <span className="inline-flex items-center gap-1 underline decoration-white/50 underline-offset-2 group-hover:decoration-white">
          {tr ? 'Paketleri gör' : 'View packages'}
          <span aria-hidden className="transition-transform group-hover:translate-x-0.5">→</span>
        </span>
      </div>
    </Link>
  );
}

const DOT_BG = {
  backgroundImage: 'radial-gradient(rgba(255,255,255,0.08) 1px, transparent 1px)',
  backgroundSize: '22px 22px',
};

const TRUST_ICONS = ['M9 12l2 2 4-4', 'M12 2l7 4v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6l7-4z', 'M4 12l6 6L20 6'];

function Hero({ d }: { d: Dict }) {
  return (
    <section className="relative overflow-hidden bg-brand-deep text-white">
      <div className="pointer-events-none absolute inset-0" style={DOT_BG} />
      <div
        className="pointer-events-none absolute -right-40 -top-40 h-96 w-96 rounded-full opacity-30 blur-3xl"
        style={{ background: 'radial-gradient(circle, #1C6B60, transparent 70%)' }}
      />
      <div className="container-page relative py-20 sm:py-28">
        <div className="mx-auto max-w-3xl text-center">
          <span className="badge animate-fade-up border-white/15 bg-white/10 text-white/85">
            <span className="h-1.5 w-1.5 rounded-full bg-accent" /> {d.hero.badge}
          </span>
          <h1 className="animate-fade-up mt-6 text-4xl font-extrabold leading-[1.08] sm:text-5xl md:text-[3.4rem]">
            {d.hero.titleA} <span className="text-accent">{d.hero.titleHi}</span> {d.hero.titleB}
          </h1>
          <p className="animate-fade-up mx-auto mt-6 max-w-xl text-lg leading-relaxed text-white/75">
            {d.hero.subtitle}
          </p>
          <div className="animate-fade-up mt-9 flex flex-col items-center justify-center gap-3 sm:flex-row">
            <Link href="/register" className="btn-primary w-full sm:w-auto">
              {d.hero.ctaPrimary}
            </Link>
            <Link href="#nasil-calisir" className="btn w-full border border-white/25 text-white hover:bg-white/10 sm:w-auto">
              {d.hero.ctaSecondary}
            </Link>
          </div>
        </div>

        {/* ÜCRETSİZ ANLIK ÖN-TARAMA — landing'in birincil dönüşüm kancası (pasif, gerçek, üç-durum). */}
        <div className="animate-fade-up mx-auto mt-12 max-w-2xl">
          <InstantScan />
        </div>

        <div className="mx-auto mt-12 flex max-w-2xl flex-wrap items-center justify-center gap-3">
          {d.hero.trust.map((label, i) => (
            // Yesil zemin: her rozet BEYAZ oval pill icinde -> ikon+yazi net gorunur.
            <span key={label} className="inline-flex items-center gap-2 rounded-pill bg-white px-4 py-2 text-sm font-medium text-brand shadow-sm">
              <svg viewBox="0 0 24 24" className="h-4 w-4 text-accent" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                <path d={TRUST_ICONS[i]} />
              </svg>
              {label}
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}

const STEP_ICONS = [
  'M3 12h4l3 8 4-16 3 8h4',
  'M4 6h16M4 12h16M4 18h10',
  'M12 3a4 4 0 014 4v1a5 5 0 01-8 0V7a4 4 0 014-4zM6 21v-2a6 6 0 0112 0v2',
  'M6 10V7a6 6 0 1112 0v3M5 10h14v10H5z',
];

function HowItWorks({ d }: { d: Dict }) {
  return (
    <section id="nasil-calisir" className="container-page scroll-mt-20 py-20">
      <div className="mx-auto max-w-2xl text-center">
        <p className="eyebrow">{d.steps.eyebrow}</p>
        <h2 className="mt-3 text-3xl font-extrabold text-brand sm:text-4xl">{d.steps.title}</h2>
      </div>
      <div className="mt-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
        {d.steps.items.map((s, i) => (
          <div key={s.t} className="card p-6">
            <div className="flex h-11 w-11 items-center justify-center rounded-card bg-brand-50 text-brand">
              <svg viewBox="0 0 24 24" className="h-6 w-6" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d={STEP_ICONS[i]} />
              </svg>
            </div>
            <div className="mt-4 text-xs font-bold text-accent-600">{d.steps.stepWord} {i + 1}</div>
            <h3 className="mt-1 font-bold text-ink">{s.t}</h3>
            <p className="mt-2 text-sm leading-relaxed text-ink-soft">{s.d}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

const WHY_ICONS = [
  'M12 2l7 4v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6l7-4zM9 12l2 2 4-4',
  'M12 2l7 4v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6l7-4zM12 8v4M12 15h.01',
  'M6 10V7a6 6 0 1112 0v3M5 10h14v10H5zM12 14v3',
];

function WhyUs({ d }: { d: Dict }) {
  return (
    <section id="neden-biz" className="scroll-mt-20 bg-brand-50/60 py-20">
      <div className="container-page">
        <div className="mx-auto max-w-2xl text-center">
          <p className="eyebrow">{d.why.eyebrow}</p>
          <h2 className="mt-3 text-3xl font-extrabold text-brand sm:text-4xl">{d.why.title}</h2>
          <p className="mt-4 text-ink-soft">{d.why.subtitle}</p>
        </div>
        <div className="mt-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {d.why.items.map((r, i) => (
            <div key={r.t} className={`card p-6 ${i === 0 ? 'border-brand-300 shadow-glow' : ''}`}>
              <div className={`flex h-11 w-11 items-center justify-center rounded-card ${i === 0 ? 'bg-brand text-accent' : 'bg-brand-50 text-brand'}`}>
                <svg viewBox="0 0 24 24" className="h-6 w-6" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
                  <path d={WHY_ICONS[i]} />
                </svg>
              </div>
              <h3 className="mt-4 font-bold text-ink">{r.t}</h3>
              <p className="mt-2 text-sm leading-relaxed text-ink-soft">{r.d}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

// (FARK / REKLAM) Bizi ayıran şey: rapor + ÇÖZÜM. Çoğu tarayıcı bulguyu listeler; biz her bulgu
// için platforma özel, uygulamaya hazır düzeltme kodu (AI destekli) veririz. Rakip İSMİ/mutlak iddia
// YOK — "tipik tarayıcılar" gibi genel, savunulabilir bir çerçeve (dürüstlük disiplini).
function SolutionSection({ region }: { region: RegionConfig }) {
  const tr = region.lang === 'tr';
  const others = tr
    ? ['Uzun bir PDF ve bulgu listesi verir', 'Teknik jargon — önceliklendirme ve araştırma sizde', 'Nasıl düzelteceğinizi bulmak size kalır']
    : ['Hands you a long PDF and a list of findings', 'Technical jargon — prioritizing & research is on you', 'Figuring out how to fix it is left to you'];
  const us = tr
    ? ['Her bulgu için platformunuza özel, hazır düzeltme kodu', 'Nginx · Apache · IIS · Vercel · Cloudflare…', 'Kopyala–yapıştır uygula, dakikalar içinde kapat']
    : ['Ready-to-apply fix code for every finding', 'Nginx · Apache · IIS · Vercel · Cloudflare…', 'Copy–paste and close the gap in minutes'];
  return (
    <section id="cozum" className="scroll-mt-20 bg-gradient-to-b from-brand-50/50 to-white py-20">
      <div className="container-page">
        <div className="mx-auto max-w-2xl text-center">
          <p className="eyebrow">{tr ? 'Bizi ayıran şey' : 'What sets us apart'}</p>
          <h2 className="mt-3 text-3xl font-extrabold text-brand sm:text-4xl">
            {tr ? 'Sadece “sorun var” demeyiz — çözümü de veririz' : 'We don’t just flag problems — we hand you the fix'}
          </h2>
          <p className="mt-4 text-ink-soft">
            {tr
              ? 'Çoğu tarayıcı bulguları listeler ve gerisini size bırakır. Biz her bulgu için yapay zekâ destekli, platformunuza özel ve uygulamaya hazır düzeltme kodu üretiriz.'
              : 'Most scanners list findings and leave the rest to you. For every finding we generate AI-assisted, platform-specific, ready-to-apply fix code.'}
          </p>
        </div>

        <div className="mx-auto mt-12 grid max-w-4xl items-stretch gap-6 lg:grid-cols-2">
          {/* Tipik tarayıcılar */}
          <div className="card border-dashed p-6">
            <p className="text-xs font-bold uppercase tracking-wide text-ink-muted">{tr ? 'Tipik tarayıcılar' : 'Typical scanners'}</p>
            <ul className="mt-4 space-y-3 text-sm text-ink-soft">
              {others.map((t) => (
                <li key={t} className="flex items-start gap-2.5">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" className="mt-0.5 shrink-0 text-ink-muted" aria-hidden><path d="M18 6 6 18M6 6l12 12" strokeLinecap="round" /></svg>
                  <span>{t}</span>
                </li>
              ))}
            </ul>
          </div>
          {/* CyberTestify */}
          <div className="card border-brand-300 p-6 shadow-glow">
            <p className="flex items-center gap-2">
              <span className="rounded-pill bg-brand px-2.5 py-0.5 text-[10px] font-extrabold uppercase tracking-wide text-accent">CyberTestify</span>
            </p>
            <ul className="mt-4 space-y-3 text-sm font-medium text-ink">
              {us.map((t) => (
                <li key={t} className="flex items-start gap-2.5">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" className="mt-0.5 shrink-0 text-accent-600" aria-hidden><path d="M20 6 9 17l-5-5" strokeLinecap="round" strokeLinejoin="round" /></svg>
                  <span>{t}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Somut örnek: kopyala-yapıştır düzeltme kodu (gerçek Nginx başlık düzeltmesi). */}
        <div className="mx-auto mt-8 max-w-3xl overflow-hidden rounded-card border border-line shadow-sm">
          <div className="flex items-center gap-2 bg-brand-deep px-4 py-2.5 text-xs font-medium text-white/75">
            <span className="h-2.5 w-2.5 rounded-full bg-red-400/80" />
            <span className="h-2.5 w-2.5 rounded-full bg-amber-400/80" />
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-400/80" />
            <span className="ml-2">{tr ? 'Örnek düzeltme · Nginx — eksik güvenlik başlıkları' : 'Example fix · Nginx — missing security headers'}</span>
          </div>
          <pre className="overflow-x-auto bg-[#0e2a27] px-4 py-4 font-mono text-[12.5px] leading-relaxed text-emerald-200/90">
{`add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Content-Security-Policy "default-src 'self'" always;`}
          </pre>
        </div>
        <p className="mx-auto mt-3 max-w-3xl text-center text-xs text-ink-muted">
          {tr
            ? 'Raporunuzdaki her bulgu, tam olarak böyle uygulamaya hazır bir düzeltmeyle gelir.'
            : 'Every finding in your report comes with a ready-to-apply fix exactly like this.'}
        </p>
      </div>
    </section>
  );
}

function FinalCTA({ d, region }: { d: Dict; region: RegionConfig }) {
  return (
    <section className="container-page py-8 pb-20">
      <div className="relative overflow-hidden rounded-[20px] bg-brand-deep px-8 py-14 text-center text-white">
        <div className="pointer-events-none absolute inset-0" style={DOT_BG} />
        <div className="relative">
          <h2 className="text-3xl font-extrabold sm:text-4xl">{d.finalCta.title}</h2>
          <p className="mx-auto mt-3 max-w-lg text-white/75">{d.finalCta.subtitle}</p>
          <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
            <Link href="/register" className="btn-primary w-full sm:w-auto">
              {d.finalCta.primary}
            </Link>
            <Link href={`/${region.code}/packages`} className="btn w-full border border-white/25 text-white hover:bg-white/10 sm:w-auto">
              {d.finalCta.secondary}
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}

function Faq({ region }: { region: RegionConfig }) {
  const tr = region.lang === 'tr';
  const items = tr ? FAQ_TR : FAQ_EN;
  const faqLd = {
    '@context': 'https://schema.org',
    '@type': 'FAQPage',
    mainEntity: items.map((it) => ({
      '@type': 'Question',
      name: it.q,
      acceptedAnswer: { '@type': 'Answer', text: it.a },
    })),
  };
  return (
    <section className="border-t border-line bg-white">
      <div className="container-page py-16 sm:py-20">
        <div className="mx-auto max-w-3xl">
          <p className="eyebrow text-center">{tr ? 'Sık Sorulan Sorular' : 'FAQ'}</p>
          <h2 className="mt-2 text-center text-2xl font-extrabold text-brand sm:text-3xl">
            {tr ? 'Merak edilenler' : 'Frequently asked questions'}
          </h2>
          <dl className="mt-8 divide-y divide-line">
            {items.map((it) => (
              <div key={it.q} className="py-5">
                <dt className="text-base font-bold text-ink">{it.q}</dt>
                <dd className="mt-2 text-sm leading-relaxed text-ink-soft">{it.a}</dd>
              </div>
            ))}
          </dl>
        </div>
      </div>
      <JsonLd data={faqLd} />
    </section>
  );
}

export default function RegionHome({ params }: { params: { region: string } }) {
  if (!isRegionCode(params.region)) notFound();
  const region = getRegion(params.region);
  const d = getDict(region);
  return (
    <>
      <CampaignBanner region={region} />
      <Hero d={d} />
      <AutonomousSection region={region} />
      <HowItWorks d={d} />
      <SolutionSection region={region} />
      <WhyUs d={d} />
      <TrustSection region={region} />
      <Faq region={region} />
      <FinalCTA d={d} region={region} />
    </>
  );
}
