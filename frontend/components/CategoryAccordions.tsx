'use client';

import { useState } from 'react';
import Link from 'next/link';
import { getRegion } from '../config/regions';
import { formatMoney } from '../config/i18n';

type Pkg = { key: string; displayName: string; description: string; priceMinorUnit: number; currency?: string };

// Satis-odakli kategori sirasi (teknik degil). keys: o kategoriye ait paket key'leri.
const CATEGORIES: Array<{ id: string; tr: string; en: string; keys: string[]; auth: boolean }> = [
  {
    id: 'passive',
    tr: 'Pasif Taramalar',
    en: 'Passive Scans',
    keys: ['basit_tarama', 'ssl_tls', 'header_leak', 'dns_email', 'cms_cve', 'cors_cookie', 'csp_analiz', 'subdomain_takeover', 'api_discovery'],
    auth: false,
  },
  {
    id: 'compliance',
    tr: 'Uyum Kontrolleri',
    en: 'Compliance Checks',
    keys: ['kvkk_hazirlik', 'pci_hazirlik', 'iso27001_hazirlik'],
    auth: false,
  },
  {
    id: 'active',
    tr: 'Aktif Doğrulama',
    en: 'Active Verification',
    keys: ['injection_verify', 'idor_verify', 'ssrf_verify', 'file_upload_verify', 'business_logic_verify', 'race_massassign_verify', 'rce_verify'],
    auth: true,
  },
  {
    id: 'advanced',
    tr: 'İleri Seviye / Otonom',
    en: 'Advanced / Autonomous',
    keys: ['authenticated_scan', 'autonomous_pentest'],
    auth: true,
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
      {CATEGORIES.map((cat) => {
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
                  · {items.length} {tr ? 'kontrol içerir' : 'checks'}
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
              <div className="grid gap-4 border-t border-line px-5 py-5 md:grid-cols-2 lg:grid-cols-3">
                {items.map((p) => (
                  <div key={p.key} className="card flex flex-col p-5">
                    <div className="flex items-start justify-between gap-2">
                      <h3 className="text-base font-bold text-brand">{p.displayName}</h3>
                    </div>
                    {cat.auth && <div className="mt-1.5">{authBadge}</div>}
                    <p className="mt-2 flex-1 text-sm leading-relaxed text-ink-soft">{p.description}</p>
                    <div className="mt-4">
                      <span className="text-2xl font-extrabold text-ink">{formatMoney(p.priceMinorUnit, region)}</span>
                      <div className="mt-0.5 text-xs text-ink-muted">{region.currency === 'TRY' ? 'KDV Dahildir' : 'Taxes included'}</div>
                    </div>
                    <Link href="/register" className="btn-outline mt-4 w-full">
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
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
