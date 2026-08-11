'use client';

import { useState } from 'react';
import { api } from '../../lib/api';

type Existing = {
  type: 'bireysel' | 'kurumsal';
  companyName?: string | null; taxOffice?: string | null; taxNumber?: string | null;
  fullName?: string | null; nationalId?: string | null;
  address: string; invoiceEmail: string;
  status: 'requested' | 'issued' | 'sent';
} | null;

const STATUS_LABEL: Record<string, string> = {
  requested: 'Talebiniz alındı — faturanız hazırlanıp e-posta ile gönderilecektir.',
  issued: 'Faturanız kesildi; kısa süre içinde e-posta ile ulaşacaktır.',
  sent: 'Faturanız e-posta ile gönderildi.',
};

/**
 * (Fatura talebi — MANUEL) Ödemesi tamamlanmış sipariş için opsiyonel fatura bilgisi.
 * Sistem OTOMATİK e-fatura KESMEZ; bilgi toplanır, ekip elle keser/gönderir. Müşteri sonradan da girebilir.
 */
export function InvoiceRequestForm({ orderId, defaultEmail, existing }: { orderId: string; defaultEmail: string; existing: Existing }) {
  const [open, setOpen] = useState(false);
  const [type, setType] = useState<'bireysel' | 'kurumsal'>(existing?.type ?? 'bireysel');
  const [companyName, setCompanyName] = useState(existing?.companyName ?? '');
  const [taxOffice, setTaxOffice] = useState(existing?.taxOffice ?? '');
  const [taxNumber, setTaxNumber] = useState(existing?.taxNumber ?? '');
  const [fullName, setFullName] = useState(existing?.fullName ?? '');
  const [nationalId, setNationalId] = useState(existing?.nationalId ?? '');
  const [address, setAddress] = useState(existing?.address ?? '');
  const [invoiceEmail, setInvoiceEmail] = useState(existing?.invoiceEmail ?? defaultEmail ?? '');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [done, setDone] = useState<null | 'created' | 'updated'>(null);
  const [status, setStatus] = useState(existing?.status ?? null);

  const digits = (s: string) => s.replace(/\D/g, '');

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    // İstemci-tarafı doğrulama (sunucu ayrıca doğrular).
    if (!address.trim() || address.trim().length < 5) return setErr('Adres zorunludur.');
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(invoiceEmail.trim())) return setErr('Geçerli bir fatura e-postası girin.');
    if (type === 'kurumsal') {
      if (!companyName.trim()) return setErr('Ticari unvan zorunludur.');
      if (!taxOffice.trim()) return setErr('Vergi dairesi zorunludur.');
      if (!/^\d{10}$/.test(taxNumber)) return setErr('VKN 10 haneli rakam olmalıdır.');
    } else {
      if (!fullName.trim()) return setErr('Ad soyad zorunludur.');
      if (!/^\d{11}$/.test(nationalId)) return setErr('TCKN 11 haneli rakam olmalıdır.');
    }
    setBusy(true);
    try {
      const body = type === 'kurumsal'
        ? { type, companyName: companyName.trim(), taxOffice: taxOffice.trim(), taxNumber, address: address.trim(), invoiceEmail: invoiceEmail.trim() }
        : { type, fullName: fullName.trim(), nationalId, address: address.trim(), invoiceEmail: invoiceEmail.trim() };
      const res = await api.requestInvoice(orderId, body as any);
      setDone(res.updated ? 'updated' : 'created');
      setStatus((s) => s ?? 'requested');
    } catch (e: any) {
      setErr(e?.message ?? 'Talep gönderilemedi.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <section id="fatura" className="mt-8 scroll-mt-24 rounded-card border border-line bg-white p-5">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-bold text-brand">Fatura talebi</h2>
          <p className="mt-0.5 text-xs text-ink-soft">İsteğe bağlı — fatura isterseniz bilgilerinizi girin, faturanız e-posta ile gönderilir.</p>
        </div>
        {!open && (
          <button onClick={() => setOpen(true)} className="btn-outline shrink-0 text-sm">
            {existing ? 'Bilgileri düzenle' : 'Fatura talep et'}
          </button>
        )}
      </div>

      {status && (
        <p className="mt-3 rounded-card border border-emerald-200 bg-emerald-50 px-3.5 py-2 text-sm text-emerald-800">
          {STATUS_LABEL[status]}
        </p>
      )}

      {done && (
        <p className="mt-3 rounded-card border border-emerald-200 bg-emerald-50 px-3.5 py-2 text-sm font-semibold text-emerald-800">
          {done === 'updated' ? 'Fatura bilgileriniz güncellendi.' : 'Fatura talebiniz alındı; faturanız e-posta ile gönderilecektir.'}
        </p>
      )}

      {open && (
        <form onSubmit={submit} className="mt-4 space-y-3">
          <div className="flex gap-2">
            {(['bireysel', 'kurumsal'] as const).map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setType(t)}
                className={`rounded-pill border px-4 py-1.5 text-sm font-semibold transition ${type === t ? 'border-brand bg-brand text-white' : 'border-line text-ink-soft hover:border-brand-300'}`}
              >
                {t === 'bireysel' ? 'Bireysel' : 'Kurumsal'}
              </button>
            ))}
          </div>

          {type === 'kurumsal' ? (
            <div className="grid gap-2 sm:grid-cols-2">
              <input className="field sm:col-span-2" placeholder="Ticari unvan" value={companyName} onChange={(e) => setCompanyName(e.target.value)} />
              <input className="field" placeholder="Vergi dairesi" value={taxOffice} onChange={(e) => setTaxOffice(e.target.value)} />
              <input className="field" placeholder="VKN (10 hane)" inputMode="numeric" maxLength={10} value={taxNumber} onChange={(e) => setTaxNumber(digits(e.target.value).slice(0, 10))} />
            </div>
          ) : (
            <div className="grid gap-2 sm:grid-cols-2">
              <input className="field" placeholder="Ad soyad" value={fullName} onChange={(e) => setFullName(e.target.value)} />
              <input className="field" placeholder="TCKN (11 hane)" inputMode="numeric" maxLength={11} value={nationalId} onChange={(e) => setNationalId(digits(e.target.value).slice(0, 11))} />
            </div>
          )}

          <textarea className="field min-h-[70px] w-full" placeholder="Fatura adresi" value={address} onChange={(e) => setAddress(e.target.value)} />
          <input className="field w-full" type="email" placeholder="Fatura e-postası" value={invoiceEmail} onChange={(e) => setInvoiceEmail(e.target.value)} />

          {err && <p className="form-error">{err}</p>}

          <div className="flex items-center gap-2">
            <button type="submit" disabled={busy} className="btn-primary disabled:opacity-60">
              {busy ? 'Gönderiliyor…' : existing ? 'Bilgileri güncelle' : 'Fatura talep et'}
            </button>
            <button type="button" onClick={() => setOpen(false)} className="btn-ghost text-sm">Kapat</button>
          </div>
          <p className="text-[11px] text-ink-muted">
            Faturanız ekibimizce hazırlanıp e-posta ile gönderilir (otomatik e-fatura kesilmez). Sipariş başına tek talep tutulur; tekrar gönderirseniz bilgiler güncellenir.
          </p>
        </form>
      )}
    </section>
  );
}
