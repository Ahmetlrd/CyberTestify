'use client';

import { useCallback, useEffect, useState } from 'react';
import { adminApi } from '../../../lib/adminApi';
import { H1, Table, Pager, fmtDate } from '../../../components/admin/ui';

// (ÜCRETSİZ TARAMA LOGU) Ana sayfadaki anlık ön-tarama kutusuna girilen HER alan adı + sonucu.
function resultCell(r: { status: string; score: number | null; grade: string | null; findings: number | null; httpStatus: number | null }) {
  if (r.status === 'ok') {
    const color = (r.score ?? 0) >= 80 ? '#4ade80' : (r.score ?? 0) >= 55 ? '#fbbf24' : '#f87171';
    return <span style={{ color }}>{r.score ?? '—'}/100 ({r.grade ?? '—'}) · {r.findings ?? 0} bulgu</span>;
  }
  if (r.status === 'access_error') return <span style={{ color: '#fb923c' }}>Erişim hatası (HTTP {r.httpStatus})</span>;
  if (r.status === 'unreachable') return <span style={{ color: '#94a3b8' }}>Ulaşılamadı</span>;
  return <span style={{ color: '#94a3b8' }}>{r.status}</span>;
}

const sel: React.CSSProperties = { background: '#0b1120', color: '#e2e8f0', border: '1px solid #334155', borderRadius: 6, padding: '6px 8px', fontSize: 13 };

export default function AdminFreeScans() {
  const [page, setPage] = useState(1);
  const [q, setQ] = useState('');
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState('');
  const [region, setRegion] = useState('');
  const [lead, setLead] = useState(false);
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setData(null);
    adminApi.instantScanLogs(page, { q: query, status, region, lead }).then(setData).catch((e) => setError(e.message));
  }, [page, query, status, region, lead]);

  useEffect(() => { load(); }, [load]);

  async function del(id: string) {
    if (!window.confirm('Bu kaydı sil?')) return;
    try { await adminApi.instantScanLogDelete(id); load(); } catch (e: any) { setError(e.message); }
  }

  const stat: React.CSSProperties = { background: '#0f172a', border: '1px solid #334155', borderRadius: 8, padding: '10px 14px' };

  if (error) return <><H1>Ücretsiz Taramalar</H1><p style={{ color: '#fca5a5' }}>{error}</p></>;

  return (
    <>
      <H1>Ücretsiz Taramalar (ana sayfa)</H1>
      <p style={{ fontSize: 13, color: '#94a3b8', margin: '0 0 12px' }}>
        Ana sayfadaki “ücretsiz, anında tarayın” kutusuna girilen her alan adı ve sonucu. Lead/talep takibi ve
        kötüye kullanım tespiti için. (Yalnız teknik alan; müşteri/rapor verisi tutulmaz.)
      </p>

      {data && (
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 12 }}>
          <div style={stat}><b style={{ fontSize: 18 }}>{data.total}</b> <span style={{ color: '#94a3b8', fontSize: 12 }}>toplam (filtreli)</span></div>
          <div style={stat}><b style={{ fontSize: 18 }}>{data.uniqueHosts}</b> <span style={{ color: '#94a3b8', fontSize: 12 }}>benzersiz alan adı</span></div>
          <div style={stat}><b style={{ fontSize: 18, color: '#4ade80' }}>{data.last24h}</b> <span style={{ color: '#94a3b8', fontSize: 12 }}>son 24 saat</span></div>
        </div>
      )}

      {/* FİLTRELER */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap', alignItems: 'center' }}>
        <form onSubmit={(e) => { e.preventDefault(); setPage(1); setQuery(q.trim()); }} style={{ display: 'flex', gap: 6 }}>
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Alan adı ara…" style={{ ...sel, minWidth: 200 }} />
          <button type="submit" style={{ background: '#1e293b', color: '#7dd3fc', border: '1px solid #334155', borderRadius: 6, padding: '6px 12px', fontSize: 13, cursor: 'pointer' }}>Ara</button>
        </form>
        <select value={status} onChange={(e) => { setPage(1); setStatus(e.target.value); }} style={sel}>
          <option value="">Tüm sonuçlar</option>
          <option value="ok">Skorlandı (ok)</option>
          <option value="unreachable">Ulaşılamadı</option>
          <option value="access_error">Erişim hatası</option>
        </select>
        <select value={region} onChange={(e) => { setPage(1); setRegion(e.target.value); }} style={sel}>
          <option value="">Tüm bölgeler</option>
          <option value="tr">TR</option>
          <option value="de">DE</option>
          <option value="en">EN</option>
        </select>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, color: '#cbd5e1', cursor: 'pointer' }}>
          <input type="checkbox" checked={lead} onChange={(e) => { setPage(1); setLead(e.target.checked); }} /> Sadece lead (e-postalı)
        </label>
        {(query || status || region || lead) && (
          <button onClick={() => { setQ(''); setQuery(''); setStatus(''); setRegion(''); setLead(false); setPage(1); }}
            style={{ background: 'none', color: '#94a3b8', border: 'none', fontSize: 13, cursor: 'pointer' }}>filtreleri temizle</button>
        )}
      </div>

      {!data ? <p style={{ color: '#94a3b8' }}>Yükleniyor…</p> : (
        <>
          <Table
            columns={['Zaman', 'Alan adı', 'E-posta (lead)', 'Sonuç', 'Bölge', 'IP', '']}
            rows={data.items.map((r: any) => [
              fmtDate(r.createdAt),
              <span key="h" style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{r.host}</span>,
              r.email ? <span key="e" style={{ color: '#4ade80', wordBreak: 'break-all' }}>{r.email}</span> : <span key="e" style={{ color: '#475569' }}>—</span>,
              resultCell(r),
              <span key="rg" style={{ textTransform: 'uppercase', fontSize: 11, color: '#93c5fd' }}>{r.region}</span>,
              <span key="ip" style={{ color: '#64748b', fontSize: 12 }}>{r.ip ?? '—'}</span>,
              <button key="del" onClick={() => del(r.id)} title="Kaydı sil"
                style={{ background: 'none', border: '1px solid #7f1d1d', color: '#fca5a5', borderRadius: 6, padding: '2px 10px', fontSize: 12, cursor: 'pointer' }}>Sil</button>,
            ])}
          />
          {data.items.length === 0 && <p style={{ color: '#64748b', fontStyle: 'italic', fontSize: 13 }}>Kayıt yok.</p>}
          <Pager page={data.page} pageSize={data.pageSize} total={data.total} onPage={setPage} />
        </>
      )}
    </>
  );
}
