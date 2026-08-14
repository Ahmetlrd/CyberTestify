'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { adminApi } from '../../../../../lib/adminApi';
import { H1, card, fmtDate } from '../../../../../components/admin/ui';

// (GÖZLEMLENEBİLİRLİK) Bir taramanın adım-adım logu — kronolojik, renk-kodlu, filtreli.
// Hata / devre-kesici satırları görsel olarak öne çıkar. Log best-effort yazıldığından boş olabilir.

type LogRow = {
  seq: number; ts: string; step: string; level: string;
  method: string | null; url: string | null; status: number | null;
  durationMs: number | null; sizeBytes: number | null;
  rule: string | null; severity: string | null; summary: string | null;
};

const LEVEL_STYLE: Record<string, { bg: string; fg: string; label: string }> = {
  info: { bg: 'transparent', fg: '#94a3b8', label: 'bilgi' },
  warn: { bg: '#78350f22', fg: '#fbbf24', label: 'uyarı' },
  error: { bg: '#7f1d1d33', fg: '#fca5a5', label: 'hata' },
  circuit_breaker: { bg: '#9a340733', fg: '#fdba74', label: 'devre kesici' },
};

function statusColor(s: number | null): string {
  if (s == null) return '#94a3b8';
  if (s === 0) return '#fca5a5';
  if (s >= 500) return '#fca5a5';
  if (s >= 400) return '#fbbf24';
  if (s >= 300) return '#93c5fd';
  return '#86efac';
}

export default function ScanLogsPage({ params }: { params: { id: string } }) {
  const [data, setData] = useState<{ order: any; count: number; logs: LogRow[] } | null>(null);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState<'all' | 'issues'>('all');
  const [q, setQ] = useState('');

  useEffect(() => {
    adminApi.scanLogs(params.id).then(setData).catch((e) => setError(e.message));
  }, [params.id]);

  const rows = (data?.logs ?? []).filter((r) => {
    if (filter === 'issues' && r.level === 'info') return false;
    if (q && !`${r.step} ${r.url ?? ''} ${r.summary ?? ''} ${r.rule ?? ''}`.toLocaleLowerCase('tr').includes(q.toLocaleLowerCase('tr'))) return false;
    return true;
  });
  const issueCount = (data?.logs ?? []).filter((r) => r.level !== 'info').length;

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 4 }}>
        <Link href="/admin/orders" style={{ color: '#93c5fd', fontSize: 13, textDecoration: 'none' }}>← Siparişler</Link>
      </div>
      <H1>Tarama Logu</H1>
      {error && <div style={{ ...card, borderColor: '#b91c1c', color: '#fca5a5' }}>Hata: {error}</div>}
      {!data && !error && <div style={{ color: '#94a3b8' }}>Yükleniyor…</div>}
      {data && (
        <>
          <div style={{ ...card, marginBottom: 12, display: 'flex', flexWrap: 'wrap', gap: 16, alignItems: 'center' }}>
            <div><span style={{ color: '#94a3b8' }}>Hedef:</span> <b>{data.order?.domain?.hostname ?? '—'}</b></div>
            <div><span style={{ color: '#94a3b8' }}>Paket:</span> {data.order?.package?.displayName ?? '—'}</div>
            <div><span style={{ color: '#94a3b8' }}>Durum:</span> {data.order?.status ?? '—'}</div>
            <div><span style={{ color: '#94a3b8' }}>Adım:</span> <b>{data.count}</b></div>
            <div><span style={{ color: '#94a3b8' }}>Sorunlu:</span> <b style={{ color: issueCount ? '#fbbf24' : '#86efac' }}>{issueCount}</b></div>
          </div>

          <div style={{ display: 'flex', gap: 10, marginBottom: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <button onClick={() => setFilter('all')} style={tab(filter === 'all')}>Tümü ({data.count})</button>
            <button onClick={() => setFilter('issues')} style={tab(filter === 'issues')}>Yalnız hata/devre-kesici ({issueCount})</button>
            <input placeholder="ara: adım / URL / kural…" value={q} onChange={(e) => setQ(e.target.value)}
              style={{ marginLeft: 'auto', padding: '6px 10px', borderRadius: 6, background: '#0f172a', color: '#e2e8f0', border: '1px solid #334155', fontSize: 13, minWidth: 240 }} />
          </div>

          {data.count === 0 && <div style={{ ...card, color: '#94a3b8' }}>Bu tarama için log kaydı yok (best-effort yazım; eski taramalar veya log-öncesi taramalar boş olabilir).</div>}

          {data.count > 0 && (
            <div style={{ ...card, padding: 0, overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
                <thead>
                  <tr style={{ background: '#0f172a', color: '#94a3b8', textAlign: 'left' }}>
                    {['#', 'Zaman', 'Adım', 'İstek', 'Durum', 'Süre', 'Boyut', 'Kural', 'Not'].map((h) => (
                      <th key={h} style={{ padding: '8px 10px', position: 'sticky', top: 0, whiteSpace: 'nowrap' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => {
                    const ls = LEVEL_STYLE[r.level] ?? LEVEL_STYLE.info;
                    return (
                      <tr key={r.seq} style={{ background: ls.bg, borderTop: '1px solid #1e293b' }}>
                        <td style={{ padding: '6px 10px', color: '#64748b' }}>{r.seq}</td>
                        <td style={{ padding: '6px 10px', color: '#94a3b8', whiteSpace: 'nowrap' }}>{new Date(r.ts).toLocaleTimeString('tr-TR')}</td>
                        <td style={{ padding: '6px 10px', fontWeight: 600, color: '#e2e8f0' }}>
                          {r.level !== 'info' && <span style={{ display: 'inline-block', marginRight: 6, padding: '1px 6px', borderRadius: 999, fontSize: 10.5, fontWeight: 700, background: '#0f172a', color: ls.fg, border: `1px solid ${ls.fg}55` }}>{ls.label}</span>}
                          {r.step}
                        </td>
                        <td style={{ padding: '6px 10px', color: '#cbd5e1', maxWidth: 360, wordBreak: 'break-all' }}>{r.method ? <><b style={{ color: '#93c5fd' }}>{r.method}</b> {r.url}</> : (r.url ?? '')}</td>
                        <td style={{ padding: '6px 10px', fontWeight: 700, color: statusColor(r.status) }}>{r.status ?? ''}</td>
                        <td style={{ padding: '6px 10px', color: '#94a3b8', whiteSpace: 'nowrap' }}>{r.durationMs != null ? `${r.durationMs} ms` : ''}</td>
                        <td style={{ padding: '6px 10px', color: '#94a3b8', whiteSpace: 'nowrap' }}>{r.sizeBytes != null ? `${r.sizeBytes} B` : ''}</td>
                        <td style={{ padding: '6px 10px', color: '#a78bfa' }}>{r.rule ?? ''}</td>
                        <td style={{ padding: '6px 10px', color: ls.fg }}>{r.summary ?? ''}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </>
  );
}

function tab(active: boolean): React.CSSProperties {
  return { padding: '6px 12px', borderRadius: 6, fontSize: 13, fontWeight: 700, cursor: 'pointer',
    background: active ? '#1d4ed8' : '#1e293b', color: active ? '#fff' : '#94a3b8', border: `1px solid ${active ? '#3b82f6' : '#334155'}` };
}
