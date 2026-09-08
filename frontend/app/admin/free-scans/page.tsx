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
  const [suspicious, setSuspicious] = useState(false);
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [editId, setEditId] = useState<string | null>(null); // e-posta inline duzenleme
  const [editVal, setEditVal] = useState('');
  const [saving, setSaving] = useState(false);

  const load = useCallback(() => {
    setData(null);
    adminApi.instantScanLogs(page, { q: query, status, region, lead, suspicious }).then(setData).catch((e) => setError(e.message));
  }, [page, query, status, region, lead, suspicious]);

  useEffect(() => { load(); }, [load]);

  async function del(id: string) {
    if (!window.confirm('Bu kaydı sil?')) return;
    try { await adminApi.instantScanLogDelete(id); load(); } catch (e: any) { setError(e.message); }
  }

  async function saveEmail(id: string) {
    setSaving(true);
    try { await adminApi.instantScanLogSetEmail(id, editVal.trim() || null); setEditId(null); setEditVal(''); load(); }
    catch (e: any) { setError(e.message); }
    finally { setSaving(false); }
  }

  // E-posta hücresi: kalem → inline düzelt/sil (boş kaydet = sil).
  const emailCell = (r: any) => editId === r.id ? (
    <span key="e" style={{ display: 'inline-flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
      <input autoFocus value={editVal} onChange={(e) => setEditVal(e.target.value)}
        onKeyDown={(e) => { if (e.key === 'Enter') saveEmail(r.id); if (e.key === 'Escape') { setEditId(null); setEditVal(''); } }}
        placeholder="e-posta (boş = sil)"
        style={{ background: '#0b1120', color: '#e2e8f0', border: '1px solid #334155', borderRadius: 6, padding: '4px 7px', fontSize: 12, width: 180 }} />
      <button onClick={() => saveEmail(r.id)} disabled={saving} style={{ background: '#166534', color: '#dcfce7', border: 'none', borderRadius: 6, padding: '4px 9px', fontSize: 11, fontWeight: 700, cursor: 'pointer' }}>kaydet</button>
      <button onClick={() => { setEditId(null); setEditVal(''); }} style={{ background: 'none', color: '#94a3b8', border: 'none', fontSize: 11, cursor: 'pointer' }}>iptal</button>
    </span>
  ) : (
    <span key="e" style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
      {r.email
        ? <span style={{ color: '#4ade80', wordBreak: 'break-all' }}>{r.email}{r.suspicious && <span style={{ marginLeft: 6, background: '#7c2d12', color: '#fdba74', borderRadius: 999, padding: '1px 7px', fontSize: 10, fontWeight: 800, whiteSpace: 'nowrap' }}>ŞÜPHELİ</span>}</span>
        : <span style={{ color: '#475569' }}>—</span>}
      <button onClick={() => { setEditId(r.id); setEditVal(r.email ?? ''); }} title="Düzenle / sil" style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', padding: 2, display: 'inline-flex' }}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 20h9" /><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z" /></svg>
      </button>
    </span>
  );

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
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, color: '#cbd5e1', cursor: 'pointer' }}>
          <input type="checkbox" checked={suspicious} onChange={(e) => { setPage(1); setSuspicious(e.target.checked); }} /> Sadece şüpheli
        </label>
        {(query || status || region || lead || suspicious) && (
          <button onClick={() => { setQ(''); setQuery(''); setStatus(''); setRegion(''); setLead(false); setSuspicious(false); setPage(1); }}
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
              emailCell(r),
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
