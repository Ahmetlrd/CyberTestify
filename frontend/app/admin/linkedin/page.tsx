'use client';

/**
 * (LINKEDIN OTOMATİK PAYLAŞIM) Admin sekmesi — Buffer GraphQL API üzerinden LinkedIn şirket
 * sayfasına gönderi sıraya alma / belirli tarihte zamanlama.
 * API anahtarı BACKEND env'de; bu sayfa anahtarı ne görür ne saklar.
 */
import { useCallback, useEffect, useState } from 'react';
import { adminApi } from '../../../lib/adminApi';
import { H1, card, fmtDate } from '../../../components/admin/ui';

const MAX_LEN = 3000;

const STATUS_COLOR: Record<string, string> = {
  DRAFT: '#94a3b8', QUEUED: '#38bdf8', SCHEDULED: '#a78bfa', PUBLISHED: '#22c55e', FAILED: '#ef4444',
};
const STATUS_LABEL: Record<string, string> = {
  DRAFT: 'Taslak', QUEUED: 'Sırada', SCHEDULED: 'Zamanlandı', PUBLISHED: 'Yayınlandı', FAILED: 'Başarısız',
};

const input: React.CSSProperties = {
  width: '100%', padding: '8px 10px', borderRadius: 6, background: '#0f172a',
  color: '#e2e8f0', border: '1px solid #334155', fontSize: 13,
};
const btn: React.CSSProperties = {
  padding: '8px 14px', borderRadius: 6, border: '1px solid #334155',
  background: '#0f172a', color: '#e2e8f0', cursor: 'pointer', fontSize: 13, fontWeight: 600,
};

export default function AdminLinkedin() {
  const [status, setStatus] = useState<{ enabled: boolean; error?: string; channelName?: string; channelId?: string } | null>(null);
  const [data, setData] = useState<{ items: any[]; pendingCount: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState<string>(''); // durum filtresi ('' = tümü)
  const [syncing, setSyncing] = useState(false);

  const [content, setContent] = useState('');
  const [mediaUrl, setMediaUrl] = useState('');
  const [when, setWhen] = useState(''); // <input type="datetime-local"> → yerel saat
  const [assets, setAssets] = useState<any[]>([]);
  const [slidesRaw, setSlidesRaw] = useState('');
  const [carTitle, setCarTitle] = useState('');

  const load = useCallback(() => {
    adminApi.linkedinPosts().then(setData).catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    adminApi.linkedinStatus().then(setStatus).catch((e) => setStatus({ enabled: false, error: e.message }));
    adminApi.linkedinAssets().then((d) => setAssets(d.items)).catch(() => {});
    // (OTOMATİK SENKRON) Panel açılınca Buffer'daki güncel durumu çek → yayınlanan gönderi ANINDA
    // "Yayınlandı" görünür (worker zaten 20 dk'da bir de senkronlar). Best-effort; hata taramayı bozmaz.
    setSyncing(true);
    adminApi.linkedinSync().catch(() => {}).finally(() => { setSyncing(false); load(); });
  }, [load]);

  async function submit(mode: 'addToQueue' | 'customScheduled') {
    setBusy(true); setError(null); setOk(null);
    try {
      // datetime-local yerel saattir → Buffer'a UTC ISO 8601 olarak gider.
      const scheduledFor = mode === 'customScheduled' && when ? new Date(when).toISOString() : undefined;
      const r = await adminApi.linkedinCreate({
        content: content.trim(),
        mediaUrl: mediaUrl.trim() || undefined,
        mode,
        scheduledFor,
      });
      setOk(mode === 'addToQueue' ? 'Gönderi Buffer sırasına eklendi.' : `Gönderi ${fmtDate(r.post?.scheduledFor ?? null)} için zamanlandı.`);
      setContent(''); setMediaUrl(''); setWhen('');
      load();
    } catch (e: any) {
      setError(e.message);
      load(); // FAILED kaydı listede görünsün — sessiz hata YOK
    } finally { setBusy(false); }
  }

  // Slayt formati (satir bazli, ogrenmesi kolay):
  //   ---            -> yeni slayt
  //   # Baslik       -> slayt basligi
  //   > Kicker       -> ust etiket
  //   - Madde        -> madde
  //   duz satir      -> paragraf
  function parseSlides(raw: string) {
    return raw.split(/^---$/m).map((blk) => {
      const s: any = { bullets: [] as string[] };
      for (const line of blk.split('\n').map((l) => l.trim()).filter(Boolean)) {
        if (line.startsWith('# ')) s.title = line.slice(2);
        else if (line.startsWith('> ')) s.kicker = line.slice(2);
        else if (line.startsWith('- ')) s.bullets.push(line.slice(2));
        else s.body = s.body ? `${s.body} ${line}` : line;
      }
      if (!s.bullets.length) delete s.bullets;
      return s;
    }).filter((s) => s.title);
  }

  async function makeCarousel() {
    const slides = parseSlides(slidesRaw);
    if (!carTitle.trim() || slides.length < 2) { setError('Başlık ve en az 2 slayt gerekir.'); return; }
    setBusy(true); setError(null); setOk(null);
    try {
      slides[0].variant = slides[0].variant ?? 'cover';
      slides[slides.length - 1].variant = slides[slides.length - 1].variant ?? 'cta';
      const r = await adminApi.linkedinMakeCarousel({ title: carTitle.trim(), slides });
      setOk(`PDF carousel üretildi (${r.pages} sayfa). Aşağıdaki listeden gönderiye ekleyebilirsiniz.`);
      setMediaUrl(r.url); setSlidesRaw(''); setCarTitle('');
      adminApi.linkedinAssets().then((d) => setAssets(d.items)).catch(() => {});
    } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  }

  async function cancel(id: string) {
    if (!window.confirm('Gönderi Buffer’dan da silinecek. Devam edilsin mi?')) return;
    setBusy(true); setError(null); setOk(null);
    try { await adminApi.linkedinDelete(id); setOk('Gönderi iptal edildi (Buffer’dan da silindi).'); }
    catch (e: any) { setError(e.message); }
    finally { setBusy(false); load(); }
  }

  async function sync() {
    setBusy(true); setError(null); setOk(null);
    try { const r = await adminApi.linkedinSync(); setOk(`Durum senkronu: ${r.checked} gönderi kontrol edildi, ${r.updated} güncellendi.`); }
    catch (e: any) { setError(e.message); }
    finally { setBusy(false); load(); }
  }

  const items = data?.items ?? [];
  const STATUS_ORDER = ['DRAFT', 'QUEUED', 'SCHEDULED', 'PUBLISHED', 'FAILED'];
  const counts: Record<string, number> = {};
  for (const p of items) counts[p.status] = (counts[p.status] ?? 0) + 1;
  // Zaman çizelgesi: planlanan tarihe göre (yakın olan önce); tarihi olmayan (Buffer sırası) en sona.
  const sorted = [...items].sort((a, b) => {
    const ta = a.scheduledFor ? new Date(a.scheduledFor).getTime() : Infinity;
    const tb = b.scheduledFor ? new Date(b.scheduledFor).getTime() : Infinity;
    if (ta !== tb) return ta - tb;
    return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
  });
  const shown = filter ? sorted.filter((p) => p.status === filter) : sorted;

  const filterChip = (key: string, label: string, count: number) => {
    const active = filter === key;
    const c = key ? (STATUS_COLOR[key] ?? '#64748b') : '#38bdf8';
    return (
      <button key={key || 'ALL'} onClick={() => setFilter(key)} style={{
        display: 'inline-flex', alignItems: 'center', gap: 6, padding: '5px 11px', borderRadius: 999,
        fontSize: 12, fontWeight: 700, cursor: 'pointer',
        border: `1px solid ${active ? c : '#334155'}`, background: active ? c : '#0f172a',
        color: active ? '#0f172a' : '#cbd5e1',
      }}>
        {label} <span style={{ opacity: 0.75 }}>{count}</span>
      </button>
    );
  };

  const pill = (s: string) => (
    <span style={{ background: STATUS_COLOR[s] ?? '#64748b', color: '#0f172a', borderRadius: 999, padding: '2px 9px', fontSize: 11, fontWeight: 800 }}>
      {STATUS_LABEL[s] ?? s}
    </span>
  );

  const row = (p: any, withCancel: boolean) => (
    <div key={p.id} style={{ borderBottom: '1px solid #263449', padding: '10px 0', display: 'flex', gap: 12, alignItems: 'flex-start' }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          {pill(p.status)}
          <span style={{ fontSize: 12, color: '#94a3b8' }}>
            {p.scheduledFor ? `Planlanan: ${fmtDate(p.scheduledFor)}` : 'Buffer sırasına eklendi'} · Oluşturma: {fmtDate(p.createdAt)}
          </span>
        </div>
        <p style={{ margin: '6px 0 0', fontSize: 13, color: '#e2e8f0', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{p.content}</p>
        {p.mediaUrl && <p style={{ margin: '4px 0 0', fontSize: 12, color: '#64748b', wordBreak: 'break-all' }}>Görsel: {p.mediaUrl}</p>}
        {p.errorMessage && (
          <p style={{ margin: '6px 0 0', fontSize: 12, color: p.status === 'FAILED' ? '#fca5a5' : '#94a3b8', fontWeight: 600 }}>
            {p.status === 'FAILED' ? 'Hata: ' : 'Sırada: '}{p.errorMessage}
          </p>
        )}
        {p.bufferPostId && <p style={{ margin: '4px 0 0', fontSize: 11, color: '#475569' }}>Buffer id: {p.bufferPostId}</p>}
      </div>
      {withCancel && (
        <button onClick={() => cancel(p.id)} disabled={busy} style={{ ...btn, borderColor: '#7f1d1d', color: '#fca5a5' }}>İptal et</button>
      )}
    </div>
  );

  return (
    <>
      <H1>LinkedIn Paylaşımları</H1>

      {status && !status.enabled && (
        <div style={{ ...card, borderColor: '#7f1d1d', marginBottom: 16 }}>
          <strong style={{ color: '#fca5a5' }}>Buffer bağlantısı yok.</strong>
          <p style={{ margin: '6px 0 0', fontSize: 13, color: '#e2e8f0' }}>{status.error}</p>
        </div>
      )}
      {status?.enabled && (
        <p style={{ fontSize: 13, color: '#94a3b8', marginBottom: 16 }}>
          Bağlı kanal: <strong style={{ color: '#22c55e' }}>{status.channelName}</strong> (LinkedIn)
        </p>
      )}

      {error && <div style={{ ...card, borderColor: '#7f1d1d', marginBottom: 12, color: '#fca5a5', fontSize: 13 }}>{error}</div>}
      {ok && <div style={{ ...card, borderColor: '#166534', marginBottom: 12, color: '#86efac', fontSize: 13 }}>{ok}</div>}

      {/* --- Post oluşturucu --- */}
      <div style={{ ...card, marginBottom: 20 }}>
        <label style={{ fontSize: 13, color: '#94a3b8' }}>Gönderi metni</label>
        <textarea
          value={content}
          onChange={(e) => setContent(e.target.value.slice(0, MAX_LEN))}
          rows={6}
          placeholder="LinkedIn’de paylaşılacak metin…"
          style={{ ...input, marginTop: 6, resize: 'vertical', fontFamily: 'inherit', lineHeight: 1.5 }}
        />
        <div style={{ textAlign: 'right', fontSize: 12, color: content.length > MAX_LEN - 200 ? '#fbbf24' : '#64748b', marginTop: 4 }}>
          {content.length} / {MAX_LEN}
        </div>

        <label style={{ fontSize: 13, color: '#94a3b8' }}>Görsel URL (opsiyonel — herkese açık olmalı)</label>
        <input value={mediaUrl} onChange={(e) => setMediaUrl(e.target.value)} placeholder="https://… (veya aşağıdan üretin)" style={{ ...input, marginTop: 6, marginBottom: 12 }} />

        {/* (NATİF CAROUSEL) PDF sunucuda üretilir — elle dosya hazırlamak/yüklemek GEREKMEZ.
            LinkedIn dokümanı 1:1 gösterdiği için sayfalar 1080x1080 karedir. */}
        <details style={{ border: '1px solid #334155', borderRadius: 8, padding: '10px 12px', marginBottom: 12 }}>
          <summary style={{ cursor: 'pointer', fontSize: 13, color: '#38bdf8', fontWeight: 600 }}>PDF carousel üret (natif doküman gönderisi)</summary>
          <p style={{ fontSize: 12, color: '#94a3b8', margin: '8px 0' }}>
            Slaytları <code>---</code> ile ayırın. <code># Başlık</code>, <code>&gt; Üst etiket</code>, <code>- Madde</code>, düz satır = paragraf.
            İlk slayt kapak, son slayt CTA olarak biçimlenir. <b>6–12 sayfa</b> idealdir.
          </p>
          <input value={carTitle} onChange={(e) => setCarTitle(e.target.value)} placeholder="Doküman başlığı (carousel üstünde görünür)" style={{ ...input, marginBottom: 8 }} />
          <textarea value={slidesRaw} onChange={(e) => setSlidesRaw(e.target.value)} rows={8}
            placeholder={'> BOARD REPORTING\n# The one-page security report\nFour questions. Real numbers.\n---\n# Activity is not exposure\n- Patch counts are workload\n- Boards fund risk reduction'}
            style={{ ...input, resize: 'vertical', fontFamily: 'ui-monospace, Menlo, monospace', lineHeight: 1.5 }} />
          <button onClick={makeCarousel} disabled={busy} style={{ ...btn, marginTop: 8 }}>PDF üret</button>
        </details>

        {assets.length > 0 && (
          <details style={{ border: '1px solid #334155', borderRadius: 8, padding: '10px 12px', marginBottom: 12 }}>
            <summary style={{ cursor: 'pointer', fontSize: 13, color: '#38bdf8', fontWeight: 600 }}>Üretilmiş medya ({assets.length})</summary>
            <div style={{ maxHeight: 220, overflow: 'auto', marginTop: 8 }}>
              {assets.map((a) => (
                <div key={a.id} style={{ display: 'flex', gap: 8, alignItems: 'center', padding: '5px 0', borderBottom: '1px solid #263449', fontSize: 12 }}>
                  <span style={{ background: a.kind === 'pdf' ? '#a78bfa' : '#38bdf8', color: '#0f172a', borderRadius: 4, padding: '1px 6px', fontWeight: 800, fontSize: 10 }}>{a.kind.toUpperCase()}</span>
                  <span style={{ flex: 1, minWidth: 0, color: '#e2e8f0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.title}{a.pages ? ` · ${a.pages} sayfa` : ''}</span>
                  <a href={a.url} target="_blank" rel="noreferrer" style={{ color: '#94a3b8' }}>önizle</a>
                  <button onClick={() => setMediaUrl(a.url)} style={{ ...btn, padding: '3px 9px', fontSize: 11 }}>seç</button>
                </div>
              ))}
            </div>
          </details>
        )}

        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <button
            onClick={() => submit('addToQueue')}
            disabled={busy || !content.trim() || !status?.enabled}
            style={{ ...btn, background: '#38bdf8', color: '#0f172a', borderColor: '#38bdf8', opacity: busy || !content.trim() || !status?.enabled ? 0.5 : 1 }}
          >
            Sıraya Ekle
          </button>
          <div>
            <label style={{ display: 'block', fontSize: 12, color: '#94a3b8', marginBottom: 4 }}>Tarih / saat</label>
            <input type="datetime-local" value={when} onChange={(e) => setWhen(e.target.value)} style={{ ...input, width: 'auto' }} />
          </div>
          <button
            onClick={() => submit('customScheduled')}
            disabled={busy || !content.trim() || !when || !status?.enabled}
            style={{ ...btn, background: '#a78bfa', color: '#0f172a', borderColor: '#a78bfa', opacity: busy || !content.trim() || !when || !status?.enabled ? 0.5 : 1 }}
          >
            Belirli Tarihte Paylaş
          </button>
        </div>
      </div>

      {/* --- TÜM gönderiler: her durum görünür, filtrelenebilir, zaman sırasına göre --- */}
      <div style={card}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <strong style={{ color: '#fff', fontSize: 15 }}>Gönderiler ({items.length})</strong>
          {syncing && <span style={{ fontSize: 12, color: '#38bdf8' }}>Buffer ile senkronize ediliyor…</span>}
          <button onClick={sync} disabled={busy || syncing} style={{ ...btn, marginLeft: 'auto' }}>Durumları yenile</button>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', margin: '12px 0 4px' }}>
          {filterChip('', 'Tümü', items.length)}
          {STATUS_ORDER.map((st) => (counts[st] ? filterChip(st, STATUS_LABEL[st], counts[st]) : null))}
        </div>
        {shown.length === 0
          ? <p style={{ color: '#64748b', fontSize: 13, marginTop: 12 }}>{items.length === 0 ? 'Henüz gönderi yok.' : 'Bu filtrede gönderi yok.'}</p>
          : shown.map((p) => row(p, p.status !== 'PUBLISHED'))}
      </div>
    </>
  );
}