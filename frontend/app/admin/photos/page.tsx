'use client';
import { useEffect, useRef, useState } from 'react';
import { adminApi } from '../../../lib/adminApi';

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';
const imgUrl = (id: string) => `${API}/blog/images/${id}`;

type Cat = { slug: string; label: { tr: string; de: string; en: string } };
type Img = { id: string; category: string; alt: string | null; usedCount: number; width: number | null; height: number | null; createdAt: string };

// Tarayıcıda WebP'ye dönüştür + boyutlandır (uzun kenar ≤ MAX) → sayfa hızı/LCP bozulmasın.
// Dönüş: { dataBase64, width, height }. Kalite 0.82 (görsel/boyut dengesi).
const MAX_DIM = 1600;
async function toWebp(file: File): Promise<{ dataBase64: string; width: number; height: number }> {
  const bmp = await createImageBitmap(file).catch(() => null);
  if (!bmp) throw new Error('Görsel okunamadı (bozuk dosya olabilir).');
  let { width, height } = bmp;
  const scale = Math.min(1, MAX_DIM / Math.max(width, height));
  width = Math.round(width * scale); height = Math.round(height * scale);
  const canvas = document.createElement('canvas');
  canvas.width = width; canvas.height = height;
  const ctx = canvas.getContext('2d');
  if (!ctx) throw new Error('Canvas desteklenmiyor.');
  ctx.drawImage(bmp, 0, 0, width, height);
  bmp.close();
  const blob: Blob = await new Promise((resolve, reject) =>
    canvas.toBlob((b) => (b ? resolve(b) : reject(new Error('WebP üretilemedi.'))), 'image/webp', 0.82));
  const dataBase64: string = await new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result));
    r.onerror = () => reject(new Error('Dosya okunamadı.'));
    r.readAsDataURL(blob);
  });
  return { dataBase64, width, height };
}

export default function PhotosPage() {
  const [cats, setCats] = useState<Cat[]>([]);
  const [images, setImages] = useState<Img[]>([]);
  const [category, setCategory] = useState<string>('');
  const [filter, setFilter] = useState<string>('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string>('');
  const [err, setErr] = useState<string>('');
  const fileRef = useRef<HTMLInputElement>(null);

  const load = () => adminApi.blogImages(filter || undefined).then(setImages).catch((e) => setErr(e.message));
  useEffect(() => {
    adminApi.blogCategories().then((c) => { setCats(c); if (!category && c[0]) setCategory(c[0].slug); }).catch((e) => setErr(e.message));
  }, []); // eslint-disable-line
  useEffect(() => { load(); }, [filter]); // eslint-disable-line

  async function onUpload(files: FileList | null) {
    if (!files?.length) return;
    if (!category) { setErr('Önce kategori seç.'); return; }
    setBusy(true); setErr(''); setMsg('');
    let ok = 0, fail = 0;
    for (const f of Array.from(files)) {
      try {
        const { dataBase64, width, height } = await toWebp(f);
        await adminApi.blogImageUpload({ category, dataBase64, width, height });
        ok++;
      } catch (e) { fail++; setErr(`"${f.name}": ${(e as Error).message}`); }
    }
    setMsg(`${ok} görsel yüklendi${fail ? `, ${fail} başarısız` : ''} — kategori: ${label(category)}.`);
    setBusy(false);
    if (fileRef.current) fileRef.current.value = '';
    load();
  }

  const label = (slug: string) => cats.find((c) => c.slug === slug)?.label.tr ?? slug;
  const grouped = cats.map((c) => ({ cat: c, items: images.filter((i) => i.category === c.slug) })).filter((g) => g.items.length || !filter);

  return (
    <div style={{ maxWidth: 1100, margin: '0 auto', padding: '8px 4px' }}>
      <h1 style={{ fontSize: 22, marginBottom: 4 }}>Fotolar</h1>
      <p style={{ color: '#94a3b8', fontSize: 13, marginTop: 0 }}>
        Kategori-etiketli görsel kütüphanesi. Yüklerken görseller otomatik <b>WebP</b>'ye çevrilir ve küçültülür
        (sayfa hızı bozulmaz). Bir makale yayınlanınca, içeriğinden tahmin edilen kategoriye uygun bir görsel
        <b> kapak</b> olarak atanır (og:image dahil).
      </p>

      <div style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 10, padding: 14, margin: '12px 0' }}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <label style={{ fontSize: 13, color: '#cbd5e1' }}>Kategori:</label>
          <select value={category} onChange={(e) => setCategory(e.target.value)} style={sel}>
            {cats.map((c) => <option key={c.slug} value={c.slug}>{c.label.tr}</option>)}
          </select>
          <input ref={fileRef} type="file" accept="image/*" multiple disabled={busy}
            onChange={(e) => onUpload(e.target.files)} style={{ fontSize: 13, color: '#cbd5e1' }} />
          {busy && <span style={{ color: '#F5A623', fontSize: 13 }}>Yükleniyor…</span>}
        </div>
        {msg && <p style={{ color: '#4ade80', fontSize: 12, margin: '8px 0 0' }}>{msg}</p>}
        {err && <p style={{ color: '#f87171', fontSize: 12, margin: '8px 0 0' }}>{err}</p>}
      </div>

      <div style={{ display: 'flex', gap: 8, alignItems: 'center', margin: '4px 0 12px', flexWrap: 'wrap' }}>
        <span style={{ fontSize: 12, color: '#94a3b8' }}>Filtre:</span>
        <button onClick={() => setFilter('')} style={chip(!filter)}>Tümü ({images.length})</button>
        {cats.map((c) => <button key={c.slug} onClick={() => setFilter(c.slug)} style={chip(filter === c.slug)}>{c.label.tr}</button>)}
      </div>

      {grouped.map(({ cat, items }) => (
        <div key={cat.slug} style={{ marginBottom: 18 }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: '#7dd3fc', marginBottom: 6 }}>{cat.label.tr} <span style={{ color: '#64748b', fontWeight: 400 }}>· {items.length}</span></div>
          {items.length === 0 ? <p style={{ color: '#64748b', fontSize: 12, fontStyle: 'italic' }}>Bu kategoride görsel yok.</p> : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(150px,1fr))', gap: 10 }}>
              {items.map((im) => (
                <div key={im.id} style={{ border: '1px solid #334155', borderRadius: 8, overflow: 'hidden', background: '#0b1120' }}>
                  <img src={imgUrl(im.id)} alt={im.alt ?? ''} loading="lazy" style={{ width: '100%', height: 110, objectFit: 'cover', display: 'block' }} />
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '5px 8px' }}>
                    <span style={{ fontSize: 10, color: '#64748b' }}>{im.width}×{im.height} · {im.usedCount}× kullanıldı</span>
                    <button onClick={async () => { if (confirm('Görseli sil?')) { await adminApi.blogImageDelete(im.id).catch(() => {}); load(); } }}
                      style={{ background: 'none', border: 'none', color: '#f87171', cursor: 'pointer', fontSize: 12 }}>sil</button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

const sel: React.CSSProperties = { background: '#0b1120', color: '#e2e8f0', border: '1px solid #334155', borderRadius: 6, padding: '5px 8px', fontSize: 13 };
const chip = (active: boolean): React.CSSProperties => ({
  padding: '3px 10px', borderRadius: 999, fontSize: 12, cursor: 'pointer',
  border: `1px solid ${active ? '#F5A623' : '#334155'}`, background: active ? '#1a1206' : '#0f172a', color: active ? '#F5A623' : '#94a3b8',
});
