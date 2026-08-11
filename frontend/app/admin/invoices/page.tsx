'use client';

import { useEffect, useState } from 'react';
import { adminApi } from '../../../lib/adminApi';
import { H1, card, fmtDate } from '../../../components/admin/ui';

const STATUSES = ['', 'requested', 'issued', 'sent'];
const STATUS_LABEL: Record<string, string> = { requested: 'Talep edildi', issued: 'Kesildi', sent: 'Gönderildi' };

function money(minor: number, currency: string): string {
  try { return new Intl.NumberFormat('tr-TR', { style: 'currency', currency }).format(minor / 100); } catch { return `${(minor / 100).toFixed(2)} ${currency}`; }
}

export default function AdminInvoices() {
  const [status, setStatus] = useState('');
  const [data, setData] = useState<{ total: number; pendingCount: number; items: any[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [notes, setNotes] = useState<Record<string, string>>({});

  function load() {
    adminApi.invoiceRequests(status).then(setData).catch((e) => setError(e.message));
  }
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [status]);

  async function update(id: string, next: { status?: 'issued' | 'sent'; notes?: string }) {
    setBusyId(id); setError(null);
    try { await adminApi.updateInvoice(id, next); load(); }
    catch (e: any) { setError(e.message); }
    finally { setBusyId(null); }
  }

  const label = (k: string, v: any) => (
    <div style={{ display: 'flex', gap: 8, fontSize: 13, padding: '2px 0' }}>
      <span style={{ color: '#94a3b8', minWidth: 130 }}>{k}</span>
      <span style={{ color: '#e2e8f0', fontWeight: 600, wordBreak: 'break-word' }}>{v ?? '—'}</span>
    </div>
  );

  return (
    <>
      <H1>Fatura Talepleri</H1>
      <div style={{ marginBottom: 12, display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <div>
          <label style={{ fontSize: 13, color: '#94a3b8', marginRight: 8 }}>Durum:</label>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            style={{ padding: '6px 10px', borderRadius: 6, background: '#0f172a', color: '#e2e8f0', border: '1px solid #334155', fontSize: 13 }}
          >
            {STATUSES.map((s) => <option key={s} value={s}>{s ? STATUS_LABEL[s] : 'Tümü'}</option>)}
          </select>
        </div>
        {data && (
          <span style={{ fontSize: 13, color: '#fbbf24', fontWeight: 700 }}>
            Bekleyen (kesilecek): {data.pendingCount}
          </span>
        )}
      </div>

      {error && <p style={{ color: '#f87171', fontSize: 13 }}>{error}</p>}
      {data && data.items.length === 0 && <p style={{ color: '#94a3b8', fontSize: 14 }}>Fatura talebi yok.</p>}

      <div style={{ display: 'grid', gap: 12 }}>
        {data?.items.map((it) => (
          <div key={it.id} style={{ ...card }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8, marginBottom: 8 }}>
              <div style={{ fontWeight: 800, color: '#e2e8f0' }}>
                {money(it.amountMinorUnit, it.currency)} · {it.packageName}
              </div>
              <span style={{
                fontSize: 12, fontWeight: 700, padding: '3px 10px', borderRadius: 999,
                background: it.status === 'sent' ? '#064e3b' : it.status === 'issued' ? '#1e3a8a' : '#78350f',
                color: it.status === 'sent' ? '#6ee7b7' : it.status === 'issued' ? '#93c5fd' : '#fcd34d',
              }}>{STATUS_LABEL[it.status]}</span>
            </div>

            <div style={{ display: 'grid', gap: 2, gridTemplateColumns: '1fr', marginBottom: 10 }}>
              {label('Sipariş no', it.orderId)}
              {label('Hedef', it.hostname)}
              {label('Müşteri e-posta', it.customerEmail)}
              {label('Fatura tipi', it.type === 'kurumsal' ? 'Kurumsal' : 'Bireysel')}
              {it.type === 'kurumsal' ? (
                <>
                  {label('Ticari unvan', it.companyName)}
                  {label('Vergi dairesi', it.taxOffice)}
                  {label('VKN', it.taxNumber)}
                </>
              ) : (
                <>
                  {label('Ad soyad', it.fullName)}
                  {label('TCKN', it.nationalId)}
                </>
              )}
              {label('Adres', it.address)}
              {label('Fatura e-posta', it.invoiceEmail)}
              {label('Talep tarihi', fmtDate(it.requestedAt))}
              {it.issuedAt && label('Kesildi', fmtDate(it.issuedAt))}
              {it.sentAt && label('Gönderildi', fmtDate(it.sentAt))}
            </div>

            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
              <input
                placeholder="Not (opsiyonel)"
                defaultValue={it.notes ?? ''}
                onChange={(e) => setNotes((n) => ({ ...n, [it.id]: e.target.value }))}
                style={{ flex: 1, minWidth: 180, padding: '6px 10px', borderRadius: 6, background: '#0f172a', color: '#e2e8f0', border: '1px solid #334155', fontSize: 13 }}
              />
              <button
                disabled={busyId === it.id || it.status !== 'requested'}
                onClick={() => update(it.id, { status: 'issued', notes: notes[it.id] })}
                style={{ padding: '6px 12px', borderRadius: 6, background: it.status === 'requested' ? '#1e3a8a' : '#334155', color: '#e2e8f0', border: 'none', fontSize: 13, fontWeight: 600, cursor: it.status === 'requested' ? 'pointer' : 'default' }}
              >Kesildi olarak işaretle</button>
              <button
                disabled={busyId === it.id || it.status === 'sent'}
                onClick={() => update(it.id, { status: 'sent', notes: notes[it.id] })}
                style={{ padding: '6px 12px', borderRadius: 6, background: it.status !== 'sent' ? '#065f46' : '#334155', color: '#e2e8f0', border: 'none', fontSize: 13, fontWeight: 600, cursor: it.status !== 'sent' ? 'pointer' : 'default' }}
              >Gönderildi olarak işaretle</button>
              {notes[it.id] !== undefined && notes[it.id] !== (it.notes ?? '') && (
                <button
                  disabled={busyId === it.id}
                  onClick={() => update(it.id, { notes: notes[it.id] })}
                  style={{ padding: '6px 12px', borderRadius: 6, background: '#334155', color: '#e2e8f0', border: 'none', fontSize: 13, cursor: 'pointer' }}
                >Notu kaydet</button>
              )}
            </div>
          </div>
        ))}
      </div>
    </>
  );
}
