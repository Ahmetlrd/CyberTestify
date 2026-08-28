'use client';

import { useEffect, useState } from 'react';
import { adminApi } from '../../../lib/adminApi';
import { H1, Table, fmtDate } from '../../../components/admin/ui';

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';
const coverUrl = (id: string) => `${API}/blog/images/${id}`;

export default function AdminBlog() {
  const [data, setData] = useState<any>(null);
  const [text, setText] = useState('');
  const [lang, setLang] = useState<'tr' | 'de' | 'en'>('tr'); // yeni yükleme/yayın hangi dile/bölgeye ait
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ created: any[]; conflicts: string[]; errors: string[] } | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Kapak override: belirli görsel seçme modal'ı (post'un kategorisindeki görseller).
  const [picker, setPicker] = useState<{ postId: string; category: string | null } | null>(null);
  const [pickerImgs, setPickerImgs] = useState<any[]>([]);

  async function reroll(postId: string) {
    try { await adminApi.blogCoverReroll(postId); load(); } catch (e: any) { setError(e.message); }
  }
  async function openPicker(postId: string, category: string | null) {
    setPicker({ postId, category });
    setPickerImgs(await adminApi.blogImages(category || undefined).catch(() => []));
  }
  async function pick(imageId: string) {
    if (!picker) return;
    try { await adminApi.blogCoverSet(picker.postId, imageId); setPicker(null); load(); } catch (e: any) { setError(e.message); }
  }
  // Taslak düzenle/sil (yayınlanmışa dokunulmaz — backend garanti eder; UI de butonu göstermez).
  const [editing, setEditing] = useState<{ id: string; title: string; description: string; contentMd: string; category: string } | null>(null);
  const [saving, setSaving] = useState(false);
  async function openEdit(id: string) {
    try { const p = await adminApi.blogGet(id); setEditing({ id, title: p.title, description: p.description, contentMd: p.contentMd, category: p.category ?? '' }); }
    catch (e: any) { setError(e.message); }
  }
  async function saveEdit() {
    if (!editing) return;
    setSaving(true);
    try { await adminApi.blogUpdate(editing.id, { title: editing.title, description: editing.description, contentMd: editing.contentMd, category: editing.category || undefined }); setEditing(null); load(); }
    catch (e: any) { setError(e.message); } finally { setSaving(false); }
  }
  async function del(id: string, title: string) {
    if (!confirm(`Taslağı sil?\n"${title}"\n(Yalnız taslak silinir; yayınlanmışa dokunulmaz.)`)) return;
    try { await adminApi.blogDelete(id); load(); } catch (e: any) { setError(e.message); }
  }

  function load() {
    adminApi.blogList(lang).then(setData).catch((e) => setError(e.message));
  }
  // Dil sekmesi değişince liste + istatistik o dile göre yeniden yüklenir.
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [lang]);

  async function upload() {
    if (!text.trim() || busy) return;
    setBusy(true); setResult(null); setNote(null); setError(null);
    try {
      const r = await adminApi.blogBulk(text, lang);
      setResult(r);
      if (r.created.length) setText(''); // basarili yuklemede kutuyu temizle
      load();
    } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  }

  async function publishNext() {
    if (!confirm(`Sıradaki (en eski) ${lang.toUpperCase()} taslağını ŞİMDİ yayınla?`)) return;
    setNote(null); setError(null);
    try {
      const r = await adminApi.blogPublishNext(lang);
      setNote(r.published ? `Yayınlandı: "${r.published.title}" (/${r.published.slug})` : (r.message ?? 'Sırada taslak yok.'));
      load();
    } catch (e: any) { setError(e.message); }
  }

  const miniBtn: React.CSSProperties = { background: '#0b1120', border: '1px solid #334155', color: '#7dd3fc', borderRadius: 5, padding: '2px 6px', fontSize: 10, cursor: 'pointer', whiteSpace: 'nowrap' };
  const editLbl: React.CSSProperties = { display: 'block', fontSize: 11, color: '#94a3b8', margin: '8px 0 3px' };
  const editInput: React.CSSProperties = { width: '100%', background: '#0b1120', color: '#e2e8f0', border: '1px solid #334155', borderRadius: 6, padding: '7px 9px', fontSize: 13 };
  const box: React.CSSProperties = { background: '#0f172a', border: '1px solid #334155', borderRadius: 8, padding: 14, marginBottom: 16 };
  const badge = (s: string) => ({ background: s === 'published' ? '#166534' : s === 'draft' ? '#7c5e10' : '#334155', color: '#e2e8f0', padding: '2px 8px', borderRadius: 999, fontSize: 11 });

  return (
    <>
      <H1>Blog</H1>
      {error && <p style={{ color: '#fca5a5' }}>{error}</p>}

      {/* (Çok-dilli) Dil/bölge sekmesi — LİSTE, YÜKLEME ve YAYINLAMA hepsi seçili dile göre çalışır. */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        {([['tr', '🇹🇷 Türkçe'], ['de', '🇩🇪 Deutsch'], ['en', '🇬🇧 English']] as const).map(([code, label]) => (
          <button
            key={code}
            onClick={() => { setLang(code); setResult(null); setNote(null); }}
            style={{
              padding: '6px 14px', borderRadius: 8, fontSize: 13, fontWeight: 600, cursor: 'pointer',
              border: '1px solid ' + (lang === code ? '#3b82f6' : '#334155'),
              background: lang === code ? '#1e3a8a' : '#0f172a',
              color: lang === code ? '#dbeafe' : '#94a3b8',
            }}
          >
            {label}
          </button>
        ))}
      </div>

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
        {/* (Çok-dilli) Yükleme, üstteki DİL SEKMESİNE (şu an: {lang}) yapılır → yalnız /{lang}/blog'da görünür. */}
        <p style={{ color: '#93c5fd', fontSize: 12, margin: '0 0 8px' }}>
          Yükleme hedefi: <strong style={{ textTransform: 'uppercase' }}>{lang}</strong> (üstteki dil sekmesi). Her dil kendi <code>/{lang}/blog</code> rotasında yayınlanır ve her gün otomatik 1 makale her dile ayrı yayınlanır.
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
          columns={['Başlık', 'Dil', 'Kapak', 'Kategori', 'Slug', 'Durum', 'Yayınlandı', 'İşlem']}
          rows={data.posts.map((p: any) => [
            p.title,
            <span key="lg" style={{ background: '#1e293b', color: '#93c5fd', padding: '2px 8px', borderRadius: 999, fontSize: 11, textTransform: 'uppercase' }}>{p.lang ?? 'tr'}</span>,
            <div key="cv" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              {p.coverImageId
                ? <img src={coverUrl(p.coverImageId)} alt="" style={{ width: 46, height: 30, objectFit: 'cover', borderRadius: 4, border: p.coverManual ? '2px solid #F5A623' : '1px solid #334155' }} />
                : <span style={{ width: 46, height: 30, borderRadius: 4, border: '1px dashed #475569', display: 'inline-block' }} />}
              <span style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <button onClick={() => reroll(p.id)} title="Kategoriden rastgele yeniden seç" style={miniBtn}>🎲 yeniden</button>
                <button onClick={() => openPicker(p.id, p.category)} title="Belirli görsel seç" style={miniBtn}>🖼 seç</button>
              </span>
            </div>,
            <span key="ct" style={{ fontSize: 11, color: '#94a3b8' }}>{p.category ?? '—'}</span>,
            p.status === 'published' ? <a key="l" href={`/${p.lang ?? 'tr'}/blog/${p.slug}`} target="_blank" rel="noopener noreferrer" style={{ color: '#60a5fa' }}>/{p.lang ?? 'tr'}/blog/{p.slug}</a> : `/${p.slug}`,
            <span key="s" style={badge(p.status)}>{p.status}</span>,
            p.publishedAt ? fmtDate(p.publishedAt) : '—',
            p.status === 'draft'
              ? <span key="op" style={{ display: 'flex', gap: 6 }}>
                  <button onClick={() => openEdit(p.id)} style={miniBtn}>düzenle</button>
                  <button onClick={() => del(p.id, p.title)} style={{ ...miniBtn, color: '#f87171', borderColor: '#7f1d1d' }}>sil</button>
                </span>
              : <span key="op" style={{ fontSize: 10, color: '#475569' }}>korumalı</span>,
          ])}
        />
      )}

      {editing && (
        <div onClick={() => setEditing(null)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 50, padding: 20 }}>
          <div onClick={(e) => e.stopPropagation()} style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 10, padding: 16, width: 'min(900px,95vw)', maxHeight: '90vh', overflow: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <b style={{ color: '#e2e8f0' }}>Taslağı düzenle</b>
              <button onClick={() => setEditing(null)} style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: 18 }}>×</button>
            </div>
            <label style={editLbl}>Başlık</label>
            <input value={editing.title} onChange={(e) => setEditing({ ...editing, title: e.target.value })} style={editInput} />
            <label style={editLbl}>Meta açıklama (SEO ~155 karakter)</label>
            <input value={editing.description} onChange={(e) => setEditing({ ...editing, description: e.target.value })} style={editInput} />
            <label style={editLbl}>Kategori (boş bırakılırsa içerikten tahmin edilir)</label>
            <input value={editing.category} onChange={(e) => setEditing({ ...editing, category: e.target.value })} placeholder="ör. web-guvenligi" style={editInput} />
            <label style={editLbl}>İçerik (Markdown)</label>
            <textarea value={editing.contentMd} onChange={(e) => setEditing({ ...editing, contentMd: e.target.value })} rows={18} style={{ ...editInput, fontFamily: 'ui-monospace,monospace', fontSize: 12, resize: 'vertical' }} />
            <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
              <button onClick={saveEdit} disabled={saving} style={{ ...miniBtn, padding: '7px 16px', fontSize: 13, background: '#166534', color: '#e2e8f0', borderColor: '#166534' }}>{saving ? 'Kaydediliyor…' : 'Kaydet'}</button>
              <button onClick={() => setEditing(null)} style={{ ...miniBtn, padding: '7px 16px', fontSize: 13 }}>İptal</button>
            </div>
          </div>
        </div>
      )}

      {picker && (
        <div onClick={() => setPicker(null)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 50 }}>
          <div onClick={(e) => e.stopPropagation()} style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 10, padding: 16, maxWidth: 720, maxHeight: '80vh', overflow: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <b style={{ color: '#e2e8f0' }}>Kapak seç {picker.category ? `— ${picker.category}` : ''}</b>
              <button onClick={() => setPicker(null)} style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: 18 }}>×</button>
            </div>
            {pickerImgs.length === 0 ? <p style={{ color: '#64748b', fontSize: 13 }}>Bu kategoride görsel yok. Fotolar sayfasından ekleyebilirsin.</p> : (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(120px,1fr))', gap: 8 }}>
                {pickerImgs.map((im: any) => (
                  <img key={im.id} src={coverUrl(im.id)} alt="" onClick={() => pick(im.id)}
                    style={{ width: '100%', height: 80, objectFit: 'cover', borderRadius: 6, border: '1px solid #334155', cursor: 'pointer' }} />
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
