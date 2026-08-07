'use client';

import { useEffect, useState } from 'react';
import { adminApi } from '../../../lib/adminApi';
import { H1, Table, fmtDate } from '../../../components/admin/ui';

export default function AdminBlog() {
  const [data, setData] = useState<any>(null);
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ created: any[]; conflicts: string[]; errors: string[] } | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function load() {
    adminApi.blogList().then(setData).catch((e) => setError(e.message));
  }
  useEffect(() => { load(); /* eslint-disable-next-line */ }, []);

  async function upload() {
    if (!text.trim() || busy) return;
    setBusy(true); setResult(null); setNote(null); setError(null);
    try {
      const r = await adminApi.blogBulk(text);
      setResult(r);
      if (r.created.length) setText(''); // basarili yuklemede kutuyu temizle
      load();
    } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  }

  async function publishNext() {
    if (!confirm('Sıradaki (en eski) taslağı ŞİMDİ yayınla?')) return;
    setNote(null); setError(null);
    try {
      const r = await adminApi.blogPublishNext();
      setNote(r.published ? `Yayınlandı: "${r.published.title}" (/${r.published.slug})` : (r.message ?? 'Sırada taslak yok.'));
      load();
    } catch (e: any) { setError(e.message); }
  }

  const box: React.CSSProperties = { background: '#0f172a', border: '1px solid #334155', borderRadius: 8, padding: 14, marginBottom: 16 };
  const badge = (s: string) => ({ background: s === 'published' ? '#166534' : s === 'draft' ? '#7c5e10' : '#334155', color: '#e2e8f0', padding: '2px 8px', borderRadius: 999, fontSize: 11 });

  return (
    <>
      <H1>Blog</H1>
      {error && <p style={{ color: '#fca5a5' }}>{error}</p>}

      {/* Istatistik */}
      {data && (
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 16, fontSize: 13, color: '#cbd5e1' }}>
          <span>Sırada (taslak): <strong style={{ color: '#fbbf24' }}>{data.draftCount}</strong></span>
          <span>Yayınlanmış: <strong style={{ color: '#4ade80' }}>{data.publishedCount}</strong></span>
          <span>Son yayın: <strong>{data.lastPublishedAt ? fmtDate(data.lastPublishedAt) : '—'}</strong></span>
          <button onClick={publishNext} style={{ padding: '4px 12px', borderRadius: 6, background: '#1e3a8a', color: '#dbeafe', border: '1px solid #3b82f6', fontSize: 12, cursor: 'pointer' }}>
            Şimdi yayınla (sıradaki)
          </button>
        </div>
      )}
      {note && <p style={{ color: '#a3e635', fontSize: 13, marginBottom: 12 }}>{note}</p>}

      {/* Toplu yukleme */}
      <div style={box}>
        <p style={{ color: '#e2e8f0', fontSize: 14, fontWeight: 600, margin: '0 0 4px' }}>Toplu makale yükle (front-matter)</p>
        <p style={{ color: '#94a3b8', fontSize: 12, margin: '0 0 8px' }}>
          Her makale <code style={{ color: '#fbbf24' }}>---</code> ile başlayan bir front-matter (title, description, slug) + ardından markdown içerik. Birden fazlasını ard arda yapıştırabilirsiniz. <code>draft</code> olarak eklenir; slug otomatik normalize edilir (Türkçe karakter → ascii).
        </p>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={12}
          placeholder={'---\ntitle: "KVKK Uyumu İçin 5 Adım"\ndescription: "..."\nslug: "kvkk-uyumu-5-adim"\n---\nMakale içeriği (markdown)...\n\n---\ntitle: "İkinci Makale"\n...'}
          style={{ width: '100%', background: '#020617', color: '#e2e8f0', border: '1px solid #334155', borderRadius: 6, padding: 10, fontFamily: 'ui-monospace, Menlo, monospace', fontSize: 13, resize: 'vertical' }}
        />
        <button onClick={upload} disabled={busy || !text.trim()} style={{ marginTop: 10, padding: '8px 16px', borderRadius: 6, background: '#15803d', color: '#dcfce7', border: '1px solid #22c55e', fontSize: 13, cursor: 'pointer', opacity: busy || !text.trim() ? 0.5 : 1 }}>
          {busy ? 'Yükleniyor…' : 'Taslak olarak yükle'}
        </button>

        {result && (
          <div style={{ marginTop: 12, fontSize: 13 }}>
            {result.created.length > 0 && (
              <p style={{ color: '#4ade80' }}>✓ {result.created.length} makale taslak olarak eklendi: {result.created.map((c) => c.slug).join(', ')}</p>
            )}
            {result.conflicts.length > 0 && (
              <div style={{ color: '#fbbf24' }}>⚠ Atlanan (slug çakışması):<ul style={{ margin: '4px 0 0 18px' }}>{result.conflicts.map((c, i) => <li key={i}>{c}</li>)}</ul></div>
            )}
            {result.errors.length > 0 && (
              <div style={{ color: '#fca5a5' }}>Hatalar:<ul style={{ margin: '4px 0 0 18px' }}>{result.errors.map((c, i) => <li key={i}>{c}</li>)}</ul></div>
            )}
            {result.created.length === 0 && result.conflicts.length === 0 && result.errors.length === 0 && (
              <p style={{ color: '#94a3b8' }}>Ayrıştırılabilir makale bulunamadı — front-matter formatını kontrol edin.</p>
            )}
          </div>
        )}
      </div>

      {/* Liste */}
      {data && (
        <Table
          columns={['Başlık', 'Slug', 'Durum', 'Oluşturuldu', 'Yayınlandı']}
          rows={data.posts.map((p: any) => [
            p.title,
            p.status === 'published' ? <a key="l" href={`/blog/${p.slug}`} target="_blank" rel="noopener noreferrer" style={{ color: '#60a5fa' }}>/{p.slug}</a> : `/${p.slug}`,
            <span key="s" style={badge(p.status)}>{p.status}</span>,
            fmtDate(p.createdAt),
            p.publishedAt ? fmtDate(p.publishedAt) : '—',
          ])}
        />
      )}
    </>
  );
}
