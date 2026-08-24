import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import Link from 'next/link';
import { VISIBLE_REGION_CODES, isRegionCode, getRegion } from '../../../config/regions';
import { getDict } from '../../../config/i18n';
import { RedTeamGate } from '../../../components/otonom/RedTeamGate';
import { DisclaimerReveal } from '../../../components/otonom/DisclaimerReveal';
import { LiveTerminal } from '../../../components/otonom/LiveTerminal';

export function generateStaticParams() {
  return VISIBLE_REGION_CODES.map((region) => ({ region }));
}

export function generateMetadata({ params }: { params: { region: string } }): Metadata {
  const region = isRegionCode(params.region) ? getRegion(params.region) : getRegion('tr');
  const d = getDict(region).otonom;
  const url = `https://cybertestify.com/${region.code}/otonom-red-team`;
  return {
    title: d.metaTitle,
    description: d.metaDesc,
    alternates: { canonical: url },
    robots: { index: false, follow: false },
  };
}

// ————— Marka-uyarlı KOYU palet (tasarımın near-black+kırmızısı → brand-deep teal + amber) —————
const C = {
  bg: '#071613', bgAlt: '#081a16', surface: '#0e241f', surface2: '#0b201b',
  border: '#1e3b33', borderSoft: '#17322c',
  text: '#E7EEEB', textSoft: '#b7c6c0', textMuted: '#7e938c',
  amber: '#F5A623', amberHover: '#ffc152', amberSoftBg: 'rgba(245,166,35,.07)', amberSoftBorder: '#3a3320', amberGlow: 'rgba(245,166,35,.28)',
  mono: 'var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace)',
};
// Risk-semantik seviye renkleri (S1 yeşil / S2 amber / S3 kırmızı) — binder şiddet paletiyle akraba.
const LEVEL_ACCENT = ['#34d399', '#F5A623', '#f87171'];

export default function OtonomRedTeamPage({ params }: { params: { region: string } }) {
  if (!isRegionCode(params.region)) notFound();
  const region = getRegion(params.region);
  const d = getDict(region).otonom;
  const packagesHref = `/${region.code}/packages`;

  return (
    <main style={{ background: C.bg, color: C.text }}>
      {/* Animasyon keyframe'leri (LiveTerminal + hero) */}
      <style>{`
        @keyframes rtPulseDot{0%,100%{opacity:1}50%{opacity:.25}}
        @keyframes rtScanSweep{0%{transform:translateY(-100%)}100%{transform:translateY(520px)}}
        @keyframes rtRadarSpin{0%{transform:rotate(0)}100%{transform:rotate(360deg)}}
        @keyframes rtBlink{0%,49%{opacity:1}50%,100%{opacity:0}}
        @keyframes rtFloatGlow{0%,100%{opacity:.5}50%{opacity:1}}
      `}</style>

      {/* ————————————————————————— HERO ————————————————————————— */}
      <section style={{ position: 'relative', overflow: 'hidden', borderBottom: `1px solid ${C.border}` }}>
        <div style={{ position: 'absolute', inset: 0, background: `radial-gradient(ellipse 900px 500px at 75% 20%, ${C.amberSoftBg}, transparent 65%)`, pointerEvents: 'none' }} />
        <div style={{ position: 'absolute', inset: 0, backgroundImage: 'linear-gradient(rgba(255,255,255,.02) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.02) 1px, transparent 1px)', backgroundSize: '56px 56px', maskImage: 'radial-gradient(ellipse 70% 60% at 50% 30%, black, transparent)', WebkitMaskImage: 'radial-gradient(ellipse 70% 60% at 50% 30%, black, transparent)', pointerEvents: 'none' }} />
        <div className="container-page" style={{ position: 'relative', padding: '80px 0 64px' }}>
          <div className="grid items-center gap-16 lg:grid-cols-[1.1fr_.9fr]">
            <div>
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, border: `1px solid ${C.amberSoftBorder}`, background: C.amberSoftBg, color: C.amber, fontFamily: C.mono, fontSize: 12, padding: '6px 14px', borderRadius: 100, marginBottom: 24 }}>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: C.amber, animation: 'rtPulseDot 1.6s infinite' }} />
                {d.eyebrow.toLocaleUpperCase('tr')} · SINIRLI ERİŞİM
              </div>
              <h1 className="text-balance" style={{ fontSize: 52, lineHeight: 1.06, letterSpacing: '-.03em', fontWeight: 800, margin: '0 0 20px' }}>{d.title}</h1>
              <p className="text-pretty" style={{ fontSize: 18, lineHeight: 1.65, color: C.textSoft, margin: '0 0 26px', maxWidth: 520 }}>{d.subtitle}</p>
              <div style={{ display: 'flex', gap: 10, marginBottom: 30, flexWrap: 'wrap' }}>
                {d.badges.map((b) => (
                  <span key={b} style={{ fontFamily: C.mono, fontSize: 12, color: C.textSoft, border: `1px solid ${C.border}`, background: C.surface, padding: '6px 12px', borderRadius: 6 }}>{b}</span>
                ))}
              </div>
              <div style={{ display: 'flex', gap: 14, alignItems: 'center', marginBottom: 24, flexWrap: 'wrap' }}>
                <a href="#panel" style={{ background: C.amber, color: '#0a1c18', padding: '14px 30px', borderRadius: 10, fontWeight: 700, fontSize: 16, boxShadow: `0 0 32px ${C.amberGlow}` }}>{d.heroCtaPrimary} — Beta</a>
                <a href="#how" style={{ color: C.text, padding: '14px 26px', borderRadius: 10, border: `1px solid ${C.border}`, fontWeight: 600, fontSize: 15 }}>{d.heroCtaSecondary}</a>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 13, color: C.textMuted, fontFamily: C.mono }}>
                <span style={{ color: C.amber }}>⚠</span> {d.stickyWarn}
              </div>
            </div>
            <LiveTerminal />
          </div>
        </div>
      </section>

      {/* ————————————————————————— NE / KİME ————————————————————————— */}
      <section style={{ borderBottom: `1px solid ${C.border}` }}>
        <div className="container-page" style={{ padding: '64px 0' }}>
          <div className="grid gap-12 lg:grid-cols-2">
            <div>
              <div style={{ fontFamily: C.mono, fontSize: 12, color: C.amber, letterSpacing: '.14em', marginBottom: 14 }}>// NE YAPAR</div>
              <h2 style={{ fontSize: 26, letterSpacing: '-.02em', margin: '0 0 14px', fontWeight: 700 }}>{d.whatTitle}</h2>
              <p className="text-pretty" style={{ color: C.textSoft, lineHeight: 1.7, margin: 0 }}>{d.whatBody}</p>
            </div>
            <div>
              <div style={{ fontFamily: C.mono, fontSize: 12, color: C.amber, letterSpacing: '.14em', marginBottom: 14 }}>// KİMLER İÇİN</div>
              <h2 style={{ fontSize: 26, letterSpacing: '-.02em', margin: '0 0 14px', fontWeight: 700 }}>Deneysel doğayı kabul eden ekipler</h2>
              <p className="text-pretty" style={{ color: C.textSoft, lineHeight: 1.7, margin: 0 }}>{d.whatFor}</p>
            </div>
          </div>
        </div>
      </section>

      {/* ————————————————————————— S1 / S2 / S3 ————————————————————————— */}
      <section style={{ borderBottom: `1px solid ${C.border}`, background: `linear-gradient(${C.bg}, ${C.bgAlt})` }}>
        <div className="container-page" style={{ padding: '72px 0' }}>
          <div style={{ textAlign: 'center', marginBottom: 44 }}>
            <div style={{ fontFamily: C.mono, fontSize: 12, color: C.amber, letterSpacing: '.14em', marginBottom: 14 }}>// RİSK SEVİYELERİ</div>
            <h2 style={{ fontSize: 34, letterSpacing: '-.025em', margin: '0 0 12px', fontWeight: 700 }}>{d.levelsTitle}</h2>
            <p style={{ color: C.textSoft, fontSize: 16, margin: 0 }}>{d.levelsSubtitle}</p>
          </div>
          <div className="grid items-stretch gap-5 lg:grid-cols-3">
            {d.levels.map((lv, i) => {
              const accent = LEVEL_ACCENT[i] ?? C.amber;
              return (
                <div key={lv.name} style={{ position: 'relative', display: 'flex', flexDirection: 'column', background: lv.available ? '#0f2620' : C.surface2, border: `1px solid ${lv.available ? C.amberSoftBorder : C.border}`, borderRadius: 16, padding: 28, opacity: lv.available ? 1 : 0.82 }}>
                  {lv.available && (
                    <div style={{ position: 'absolute', top: -11, left: 24, background: C.amber, color: '#0a1c18', fontFamily: C.mono, fontSize: 11, fontWeight: 600, padding: '4px 12px', borderRadius: 100 }}>{lv.tag.toLocaleUpperCase('tr')}</div>
                  )}
                  <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 6 }}>
                    <div style={{ fontFamily: C.mono, fontSize: 22, fontWeight: 600, color: accent }}>{lv.name.split('·')[0].trim()}</div>
                    <div style={{ fontSize: 14, color: C.textMuted }}>{lv.name.split('·')[1]?.trim()}</div>
                  </div>
                  <div style={{ fontSize: 20, fontWeight: 700, marginBottom: 20 }}>{lv.price}</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 14, flex: 1 }}>
                    {([['RİSK', lv.risk], ['TEKNİK', lv.technique], ['TUTARLILIK', lv.consistency], ['HUMAN-IN-LOOP', lv.humanLoop]] as [string, string][]).map(([k, v]) => (
                      <div key={k} style={{ display: 'flex', gap: 10 }}>
                        <span style={{ color: accent, fontSize: 11, marginTop: 4 }}>▪</span>
                        <div>
                          <div style={{ fontSize: 12, color: C.textMuted, fontFamily: C.mono }}>{k}</div>
                          <div style={{ fontSize: 14, color: C.textSoft, lineHeight: 1.5 }}>{v}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                  {lv.note && <div style={{ marginTop: 16, fontSize: 12, color: '#f87171', lineHeight: 1.5 }}>{lv.note}</div>}
                  {lv.available ? (
                    <a href="#panel" style={{ marginTop: 22, display: 'block', textAlign: 'center', background: C.amber, color: '#0a1c18', padding: 13, borderRadius: 10, fontWeight: 700 }}>{lv.cta}</a>
                  ) : (
                    <div style={{ marginTop: 22, textAlign: 'center', border: `1px dashed ${C.border}`, color: C.textMuted, padding: 13, borderRadius: 10, fontWeight: 600, fontFamily: C.mono, fontSize: 13 }}>{lv.cta.toLocaleUpperCase('tr')}</div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* ————————————————————————— NASIL ÇALIŞIR ————————————————————————— */}
      <section id="how" style={{ borderBottom: `1px solid ${C.border}`, scrollMarginTop: 80 }}>
        <div className="container-page" style={{ padding: '72px 0' }}>
          <div style={{ fontFamily: C.mono, fontSize: 12, color: C.amber, letterSpacing: '.14em', marginBottom: 14 }}>// NASIL ÇALIŞIR</div>
          <h2 style={{ fontSize: 34, letterSpacing: '-.025em', margin: '0 0 40px', fontWeight: 700 }}>{d.howTitle}</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4" style={{ border: `1px solid ${C.border}`, borderRadius: 16, overflow: 'hidden' }}>
            {d.howSteps.map((s, i) => (
              <div key={s.t} style={{ padding: '32px 26px', borderRight: i < d.howSteps.length - 1 ? `1px solid ${C.border}` : undefined, background: C.surface2 }}>
                <div style={{ fontFamily: C.mono, fontSize: 36, fontWeight: 600, color: C.border, marginBottom: 16 }}>{String(i + 1).padStart(2, '0')}</div>
                <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 10 }}>{s.t}</div>
                <div style={{ fontSize: 14, color: C.textSoft, lineHeight: 1.65 }}>{s.d}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ————————————————————————— KANIT KATMANLARI ————————————————————————— */}
      <section style={{ borderBottom: `1px solid ${C.border}`, background: C.bgAlt }}>
        <div className="container-page" style={{ padding: '72px 0' }}>
          <div style={{ textAlign: 'center', marginBottom: 44 }}>
            <div style={{ fontFamily: C.mono, fontSize: 12, color: C.amber, letterSpacing: '.14em', marginBottom: 14 }}>// KANIT-BAĞLAMA</div>
            <h2 style={{ fontSize: 34, letterSpacing: '-.025em', margin: '0 0 12px', fontWeight: 700 }}>{d.evTitle}</h2>
            <p className="text-pretty" style={{ color: C.textSoft, fontSize: 16, margin: '0 auto', maxWidth: 560 }}>{d.principleBody}</p>
          </div>
          <div className="grid gap-5 sm:grid-cols-3">
            <EvCard color="#34d399" bg="#0c1a13" border="#1d3a28" label="KANITLI" body={d.evKanitli} glow />
            <EvCard color={C.amber} bg="#1a1608" border="#3d3216" label="BELİRSİZ" body={d.evBelirsiz} glow />
            <EvCard color="#a595c2" bg="#161320" border="#2c2433" label="HAYALET" body={d.evHayalet} />
          </div>
        </div>
      </section>

      {/* ————————————————————————— FARK TABLOSU ————————————————————————— */}
      <section style={{ borderBottom: `1px solid ${C.border}` }}>
        <div className="container-page" style={{ padding: '72px 0', maxWidth: 1000 }}>
          <div style={{ fontFamily: C.mono, fontSize: 12, color: C.amber, letterSpacing: '.14em', marginBottom: 14 }}>// 6 PAKETTEN FARKI</div>
          <h2 style={{ fontSize: 34, letterSpacing: '-.025em', margin: '0 0 16px', fontWeight: 700 }}>{d.compareTitle}</h2>
          <p className="text-pretty" style={{ color: C.textSoft, lineHeight: 1.7, margin: '0 0 32px', maxWidth: 640 }}>{d.diffBody}</p>
          <div style={{ border: `1px solid ${C.border}`, borderRadius: 16, overflow: 'hidden' }}>
            <div className="grid grid-cols-[1fr_1.2fr_1.2fr]" style={{ background: C.surface, fontFamily: C.mono, fontSize: 12, color: C.textMuted, letterSpacing: '.06em' }}>
              <div style={{ padding: '16px 22px' }} />
              <div style={{ padding: '16px 22px', borderLeft: `1px solid ${C.border}` }}>{d.compareCol1.toLocaleUpperCase('tr')}</div>
              <div style={{ padding: '16px 22px', borderLeft: `1px solid ${C.border}`, color: C.amber }}>{d.compareCol2.toLocaleUpperCase('tr')}</div>
            </div>
            {d.compareRows.map((r) => (
              <div key={r.k} className="grid grid-cols-[1fr_1.2fr_1.2fr]" style={{ borderTop: `1px solid ${C.border}`, fontSize: 14 }}>
                <div style={{ padding: '16px 22px', color: C.textMuted, fontWeight: 600 }}>{r.k}</div>
                <div style={{ padding: '16px 22px', borderLeft: `1px solid ${C.border}`, color: C.textSoft }}>{r.a}</div>
                <div style={{ padding: '16px 22px', borderLeft: `1px solid ${C.border}`, color: C.text, background: C.amberSoftBg }}>{r.b}</div>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 20 }}>
            <Link href={packagesHref} style={{ fontSize: 14, fontWeight: 600, color: C.amber }}>{d.compareLink}</Link>
          </div>
        </div>
      </section>

      {/* ————————————————————————— UYARILAR ————————————————————————— */}
      <section style={{ borderBottom: `1px solid ${C.border}`, background: `linear-gradient(${C.bg}, ${C.bgAlt})` }}>
        <div className="container-page" style={{ padding: '72px 0' }}>
          <div style={{ maxWidth: 800, margin: '0 auto', border: `1px solid ${C.amberSoftBorder}`, borderRadius: 16, background: C.amberSoftBg, padding: '36px 40px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 22 }}>
              <span style={{ fontSize: 22, color: C.amber }}>⚠</span>
              <h2 style={{ fontSize: 24, letterSpacing: '-.02em', margin: 0, fontWeight: 700 }}>{d.warnTitle}</h2>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {d.warnPoints.map((w) => (
                <div key={w} style={{ display: 'flex', gap: 14, fontSize: 15, color: C.textSoft, lineHeight: 1.65 }}>
                  <span style={{ color: C.amber, fontFamily: C.mono, marginTop: 1 }}>→</span>
                  <span>{w}</span>
                </div>
              ))}
            </div>
            <DisclaimerReveal text={d.disclaimer} word={d.triggerWord} className="mt-6" style={{ paddingTop: 22, borderTop: `1px solid ${C.borderSoft}`, fontSize: 13, color: C.textMuted, lineHeight: 1.7 }} />
          </div>
        </div>
      </section>

      {/* ————————————————————————— SATIN ALMA PANELİ ————————————————————————— */}
      <section id="panel" style={{ borderBottom: `1px solid ${C.border}`, scrollMarginTop: 80 }}>
        <div className="container-page" style={{ padding: '72px 0' }}>
          <div style={{ textAlign: 'center', marginBottom: 28 }}>
            <div style={{ fontFamily: C.mono, fontSize: 12, color: C.amber, letterSpacing: '.14em', marginBottom: 12 }}>// SATIN AL</div>
            <h2 style={{ fontSize: 30, letterSpacing: '-.025em', margin: 0, fontWeight: 700 }}>{d.principleTitle}</h2>
          </div>
          <div className="mx-auto max-w-2xl">
            <RedTeamGate d={d} />
          </div>
        </div>
      </section>

      {/* ————————————————————————— SON CTA ————————————————————————— */}
      <section style={{ position: 'relative', overflow: 'hidden' }}>
        <div style={{ position: 'absolute', inset: 0, background: `radial-gradient(ellipse 700px 360px at 50% 100%, ${C.amberSoftBg}, transparent 70%)`, pointerEvents: 'none' }} />
        <div className="container-page" style={{ position: 'relative', padding: '88px 0', textAlign: 'center' }}>
          <div style={{ fontFamily: C.mono, fontSize: 12, color: C.amber, letterSpacing: '.14em', marginBottom: 16 }}>// SINIRLI ERİŞİM</div>
          <h2 className="text-balance" style={{ fontSize: 38, letterSpacing: '-.025em', margin: '0 auto 14px', fontWeight: 700, maxWidth: 640 }}>{d.ctaBandTitle}</h2>
          <p style={{ color: C.textSoft, fontSize: 16, margin: '0 0 30px' }}>{d.levels[0].price} · {d.levels[0].name}</p>
          <a href="#panel" style={{ display: 'inline-block', background: C.amber, color: '#0a1c18', padding: '16px 44px', borderRadius: 12, fontWeight: 700, fontSize: 17, boxShadow: `0 0 48px ${C.amberGlow}` }}>{d.ctaBandBtn}</a>
        </div>
      </section>
    </main>
  );
}

function EvCard({ color, bg, border, label, body, glow }: { color: string; bg: string; border: string; label: string; body: string; glow?: boolean }) {
  return (
    <div style={{ background: bg, border: `1px solid ${border}`, borderRadius: 16, padding: 28 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <span style={{ width: 12, height: 12, borderRadius: '50%', background: color, boxShadow: glow ? `0 0 14px ${color}80` : undefined, opacity: glow ? undefined : 0.6, animation: glow ? 'rtFloatGlow 2.4s infinite' : undefined }} />
        <span style={{ fontFamily: 'var(--font-mono, ui-monospace, monospace)', fontSize: 15, fontWeight: 600, color }}>{label}</span>
      </div>
      <p style={{ color: '#b7c6c0', fontSize: 14, lineHeight: 1.7, margin: 0 }}>{body}</p>
    </div>
  );
}
