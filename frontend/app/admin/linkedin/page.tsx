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

  const [content, setContent] = useState('');
  const [mediaUrl, setMediaUrl] = useState('');
  const [when, setWhen] = useState(''); // <input type="datetime-local"> → yerel saat

  const load = useCallback(() => {
    adminApi.linkedinPosts().then(setData).catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    adminApi.linkedinStatus().then(setStatus).catch((e) => setStatus({ enabled: false, error: e.message }));
    load();
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
  const pending = items.filter((p) => p.status === 'QUEUED' || p.status === 'SCHEDULED');
  const failed = items.filter((p) => p.status === 'FAILED');
  const published = items.filter((p) => p.status === 'PUBLISHED');

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
          <p style={{ margin: '6px 0 0', fontSize: 12, color: '#fca5a5', fontWeight: 600 }}>Hata: {p.errorMessage}</p>
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
        <input value={mediaUrl} onChange={(e) => setMediaUrl(e.target.value)} placeholder="https://…" style={{ ...input, marginTop: 6, marginBottom: 12 }} />

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

      {/* --- Zamanlanmış / sırada --- */}
      <div style={{ ...card, marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 4 }}>
          <strong style={{ color: '#fff', fontSize: 15 }}>Bekleyen gönderiler ({pending.length})</strong>
          <button onClick={sync} disabled={busy} style={{ ...btn, marginLeft: 'auto' }}>Durumları yenile</button>
        </div>
        {pending.length === 0 ? <p style={{ color: '#64748b', fontSize: 13 }}>Bekleyen gönderi yok.</p> : pending.map((p) => row(p, true))}
      </div>

      {failed.length > 0 && (
        <div style={{ ...card, marginBottom: 20, borderColor: '#7f1d1d' }}>
          <strong style={{ color: '#fca5a5', fontSize: 15 }}>Başarısız ({failed.length})</strong>
          {failed.map((p) => row(p, true))}
        </div>
      )}

      <div style={card}>
        <strong style={{ color: '#fff', fontSize: 15 }}>Yayınlananlar ({published.length})</strong>
        {published.length === 0 ? <p style={{ color: '#64748b', fontSize: 13 }}>Henüz yayınlanmış gönderi yok.</p> : published.map((p) => row(p, false))}
      </div>
    </>
  );
}
