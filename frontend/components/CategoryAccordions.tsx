'use client';

import { useState } from 'react';
import Link from 'next/link';
import { getRegion } from '../config/regions';
import { formatMoney } from '../config/i18n';

type Pkg = { key: string; displayName: string; description: string; priceMinorUnit: number; currency?: string; comingSoon?: boolean; bundleOnly?: boolean; bundleName?: string | null };

// Satis-odakli kategori sirasi (teknik degil). keys: o kategoriye ait paket key'leri.
// TEK KAYNAK — hem paketler sayfasi (bu bilesen) hem /order sayfasi kullanir.
// est: kategoriye gore GERCEKCI tahmini tarama SURESI araligi (gecmis flow'lardan gozlemlenen
// mertebe; kesin taahhut DEGIL). Her pakette bir sure beklentisi bulunsun diye.
export const PACKAGE_CATEGORIES: Array<{ id: string; tr: string; en: string; keys: string[]; auth: boolean; estTr: string; estEn: string; descTr: string; descEn: string }> = [
  {
    id: 'passive',
    tr: 'Pasif Taramalar',
    en: 'Passive Scans',
    keys: ['basit_tarama', 'ssl_tls', 'header_leak', 'dns_email', 'cms_cve', 'cors_cookie', 'csp_analiz', 'subdomain_takeover', 'api_discovery'],
    auth: false,
    estTr: '~3-8 dakika',
    estEn: '~3-8 min',
    descTr: 'Hızlı görünürlük ve yapılandırma kontrolü.',
    descEn: 'Fast visibility and configuration checks.',
  },
  {
    id: 'compliance',
    tr: 'Uyum Kontrolleri',
    en: 'Compliance Checks',
    keys: ['kvkk_hazirlik', 'pci_hazirlik', 'iso27001_hazirlik'],
    auth: false,
    estTr: '~5-15 dakika',
    estEn: '~5-15 min',
    descTr: 'Hızlı görünürlük ve yapılandırmanın uyum çerçeveleriyle (KVKK/PCI/ISO) eşlenmesi. Resmi denetim değildir.',
    descEn: 'Fast visibility mapped to compliance frameworks. Not a formal audit.',
  },
  {
    id: 'active',
    tr: 'Aktif Doğrulama',
    en: 'Active Verification',
    keys: ['injection_verify', 'idor_verify', 'ssrf_verify', 'file_upload_verify', 'business_logic_verify', 'race_massassign_verify', 'rce_verify'],
    auth: true,
    estTr: '~10-25 dakika',
    estEn: '~10-25 min',
    descTr: 'Zafiyetin gerçekten var olup olmadığını zararsız şekilde doğruluyoruz (istismar etmiyoruz).',
    descEn: 'We safely verify whether a vulnerability actually exists — we do not exploit it.',
  },
  {
    id: 'advanced',
    tr: 'İleri Seviye / Otonom',
    en: 'Advanced / Autonomous',
    keys: ['authenticated_scan', 'autonomous_pentest'],
    auth: true,
    estTr: '~30-60 dakika',
    estEn: '~30-60 min',
    descTr: 'Daha derin, login’li ve çok adımlı ön değerlendirme yakında. Yine istismar ve veri sızdırma içermeyecek.',
    descEn: 'Deeper, authenticated and multi-step pre-assessment coming soon. Still no exploitation or data exfiltration.',
  },
];

export function CategoryAccordions({
  packages,
  regionCode,
  apiUrl,
}: {
  packages: Pkg[];
  regionCode: string;
  apiUrl: string;
}) {
  const region = getRegion(regionCode);
  const tr = regionCode === 'tr';
  // VARSAYILAN KAPALI (hem mobil hem masaustu). Her kategori bagimsiz acilir.
  const [open, setOpen] = useState<Record<string, boolean>>({});

  const byKey = new Map(packages.map((p) => [p.key, p]));

  const authBadge = (
    <span className="inline-flex items-center gap-1 rounded-pill bg-amber-100 px-2 py-0.5 text-[10px] font-bold text-amber-800">
      ⚠ {tr ? 'Yetkilendirme Beyanı Gerekir' : 'Authorization Declaration Required'}
    </span>
  );

  return (
    <div className="space-y-3">
      {PACKAGE_CATEGORIES.map((cat) => {
        // Yalnizca bu bolgede/satista MEVCUT paketler (ör. KVKK TR-dışı listede yok).
        const items = cat.keys.map((k) => byKey.get(k)).filter(Boolean) as Pkg[];
        if (items.length === 0) return null;
        const isOpen = !!open[cat.id];
        return (
          <div key={cat.id} className="overflow-hidden rounded-card border border-line bg-white">
            <button
              type="button"
              onClick={() => setOpen((o) => ({ ...o, [cat.id]: !o[cat.id] }))}
              aria-expanded={isOpen}
              className="flex w-full items-center justify-between gap-3 px-5 py-4 text-left transition hover:bg-brand-50/40"
            >
              <span className="flex flex-wrap items-center gap-2">
                <span className="text-base font-bold text-brand">{tr ? cat.tr : cat.en}</span>
                <span className="text-xs text-ink-muted">
                  · {items.length} {tr ? 'kontrol içerir' : 'checks'} · {tr ? 'Tahmini süre' : 'Est.'} {tr ? cat.estTr : cat.estEn}
                </span>
                {cat.auth && authBadge}
              </span>
              <svg
                width="18" height="18" viewBox="0 0 24 24" fill="none"
                className={`shrink-0 text-ink-muted transition-transform ${isOpen ? 'rotate-180' : ''}`}
                aria-hidden
              >
                <path d="M6 9l6 6 6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </button>

            {isOpen && (
              <div className="border-t border-line px-5 py-5">
                <p className="mb-4 text-sm text-ink-soft">
                  {tr ? cat.descTr : cat.descEn}
                  {cat.auth && <span className="ml-2 align-middle">{authBadge}</span>}
                </p>
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {items.map((p) => (
                  <div key={p.key} className={`card flex flex-col p-5 ${p.comingSoon ? 'opacity-90' : ''}`}>
                    <div className="flex items-start justify-between gap-2">
                      <h3 className="text-base font-bold text-brand">{p.displayName}</h3>
                      {p.comingSoon && (
                        <span className="shrink-0 rounded-pill bg-brand px-2.5 py-0.5 text-[10px] font-bold text-white">
                          {tr ? 'Yakında' : 'Soon'}
                        </span>
                      )}
                    </div>
                    {cat.auth && <div className="mt-1.5">{authBadge}</div>}
                    <p className="mt-2 flex-1 text-sm leading-relaxed text-ink-soft">{p.description}</p>
                    {p.comingSoon ? (
                      // "Yakında": fiyat gosterilmez, CTA pasif (BYOK ile ayni desen).
                      <span className="btn-ghost mt-4 w-full cursor-default">{tr ? 'Yakında' : 'Coming soon'}</span>
                    ) : p.bundleOnly ? (
                      // SATIS MODELI: tekil satis KAPALI — bu kontrol yalniz ilgili kombine paket
                      // icinde sunulur. Tekil "Satın Al" CTA'si YOK; yalniz bilgi + ornek rapor.
                      <>
                        <div className="mt-4 rounded-card border border-brand/20 bg-brand-50/50 px-3 py-2 text-xs text-ink-soft">
                          {tr
                            ? `Bu kontrol tek başına satılmaz; yalnızca ${p.bundleName ? `“${p.bundleName}”` : 'ilgili kombine paket'} içinde sunulur.`
                            : `Sold only within ${p.bundleName ? `“${p.bundleName}”` : 'its bundle'}, not individually.`}
                        </div>
                        <div className="mt-2 inline-flex items-center gap-1 text-xs text-ink-soft">
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
                            <circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" strokeLinecap="round" />
                          </svg>
                          {tr ? 'Tahmini süre:' : 'Est. time:'} {tr ? cat.estTr : cat.estEn}
                        </div>
                        <a
                          href={`${apiUrl}/orders/sample-report/${p.key}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="mt-2.5 text-center text-xs font-semibold text-accent-600 underline underline-offset-2 hover:text-accent"
                        >
                          {tr ? 'Örnek Raporu Gör (PDF)' : 'View Sample Report (PDF)'}
                        </a>
                      </>
                    ) : (
                      <>
                        <div className="mt-4">
                          <span className="text-2xl font-extrabold text-ink">{formatMoney(p.priceMinorUnit, region)}</span>
                          <div className="mt-0.5 text-xs text-ink-muted">{region.currency === 'TRY' ? 'KDV Dahildir' : 'Taxes included'}</div>
                          <div className="mt-1 inline-flex items-center gap-1 text-xs text-ink-soft">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
                              <circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" strokeLinecap="round" />
                            </svg>
                            {tr ? 'Tahmini süre:' : 'Est. time:'} {tr ? cat.estTr : cat.estEn}
                          </div>
                        </div>
                        <Link href={`/verify?package=${p.key}`} className="btn-outline mt-4 w-full">
                          {tr ? 'Satın Al' : 'Buy Now'}
                        </Link>
                        <a
                          href={`${apiUrl}/orders/sample-report/${p.key}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="mt-2.5 text-center text-xs font-semibold text-accent-600 underline underline-offset-2 hover:text-accent"
                        >
                          {tr ? 'Örnek Raporu Gör (PDF)' : 'View Sample Report (PDF)'}
                        </a>
                      </>
                    )}
                  </div>
                ))}
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
