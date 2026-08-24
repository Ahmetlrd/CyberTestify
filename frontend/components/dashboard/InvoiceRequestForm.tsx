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

const IVF = {
  tr: {
    status: { requested: 'Talebiniz alındı — faturanız hazırlanıp e-posta ile gönderilecektir.', issued: 'Faturanız kesildi; kısa süre içinde e-posta ile ulaşacaktır.', sent: 'Faturanız e-posta ile gönderildi.' } as Record<string, string>,
    title: 'Fatura talebi', sub: 'İsteğe bağlı — fatura isterseniz bilgilerinizi girin, faturanız e-posta ile gönderilir.',
    edit: 'Bilgileri düzenle', request: 'Fatura talep et',
    updated: 'Fatura bilgileriniz güncellendi.', created: 'Fatura talebiniz alındı; faturanız e-posta ile gönderilecektir.',
    individual: 'Bireysel', corporate: 'Kurumsal',
    companyName: 'Ticari unvan', taxOffice: 'Vergi dairesi', taxNumber: 'VKN (10 hane)', fullName: 'Ad soyad', nationalId: 'TCKN (11 hane)',
    address: 'Fatura adresi', email: 'Fatura e-postası',
    sending: 'Gönderiliyor…', update: 'Bilgileri güncelle', close: 'Kapat',
    foot: 'Faturanız ekibimizce hazırlanıp e-posta ile gönderilir (otomatik e-fatura kesilmez). Sipariş başına tek talep tutulur; tekrar gönderirseniz bilgiler güncellenir.',
    errAddress: 'Adres zorunludur.', errEmail: 'Geçerli bir fatura e-postası girin.', errCompany: 'Ticari unvan zorunludur.',
    errTaxOffice: 'Vergi dairesi zorunludur.', errVkn: 'VKN 10 haneli rakam olmalıdır.', errName: 'Ad soyad zorunludur.', errTckn: 'TCKN 11 haneli rakam olmalıdır.', errSend: 'Talep gönderilemedi.',
  },
  de: {
    status: { requested: 'Ihre Anfrage ist eingegangen — Ihre Rechnung wird erstellt und per E-Mail gesendet.', issued: 'Ihre Rechnung wurde ausgestellt; sie erreicht Sie in Kürze per E-Mail.', sent: 'Ihre Rechnung wurde per E-Mail gesendet.' } as Record<string, string>,
    title: 'Rechnung anfordern', sub: 'Optional — wenn Sie eine Rechnung wünschen, geben Sie Ihre Angaben ein; die Rechnung wird per E-Mail gesendet.',
    edit: 'Angaben bearbeiten', request: 'Rechnung anfordern',
    updated: 'Ihre Rechnungsangaben wurden aktualisiert.', created: 'Ihre Rechnungsanfrage ist eingegangen; die Rechnung wird per E-Mail gesendet.',
    individual: 'Privat', corporate: 'Geschäftlich',
    companyName: 'Firmenname', taxOffice: '', taxNumber: 'USt-IdNr. (optional)', fullName: 'Name', nationalId: '',
    address: 'Rechnungsadresse', email: 'Rechnungs-E-Mail',
    sending: 'Wird gesendet…', update: 'Angaben aktualisieren', close: 'Schließen',
    foot: 'Ihre Rechnung wird von unserem Team erstellt und per E-Mail gesendet. Pro Bestellung wird eine Anfrage geführt; bei erneuter Übermittlung werden die Angaben aktualisiert.',
    errAddress: 'Adresse ist erforderlich.', errEmail: 'Bitte geben Sie eine gültige Rechnungs-E-Mail ein.', errCompany: 'Firmenname ist erforderlich.',
    errTaxOffice: '', errVkn: '', errName: 'Name ist erforderlich.', errTckn: '', errSend: 'Anfrage konnte nicht gesendet werden.',
  },
} as const;

/**
 * (Fatura talebi — MANUEL) Ödemesi tamamlanmış sipariş için opsiyonel fatura bilgisi.
 * Sistem OTOMATİK e-fatura KESMEZ; bilgi toplanır, ekip elle keser/gönderir. Müşteri sonradan da girebilir.
 * /de'de Türkiye-özgü alanlar (TCKN/Vergi dairesi) gizlenir; doğrulama gevşetilir (USt-IdNr opsiyonel).
 */
export function InvoiceRequestForm({ orderId, defaultEmail, existing, lang = 'tr' }: { orderId: string; defaultEmail: string; existing: Existing; lang?: 'tr' | 'de' }) {
  const v = IVF[lang === 'de' ? 'de' : 'tr'];
  const isDe = lang === 'de';
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
    if (!address.trim() || address.trim().length < 5) return setErr(v.errAddress);
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(invoiceEmail.trim())) return setErr(v.errEmail);
    if (type === 'kurumsal') {
      if (!companyName.trim()) return setErr(v.errCompany);
      // (Türkiye-özgü) Vergi dairesi + VKN yalnız /tr'de zorunlu; /de'de USt-IdNr opsiyonel.
      if (!isDe) {
        if (!taxOffice.trim()) return setErr(v.errTaxOffice);
        if (!/^\d{10}$/.test(taxNumber)) return setErr(v.errVkn);
      }
    } else {
      if (!fullName.trim()) return setErr(v.errName);
      if (!isDe && !/^\d{11}$/.test(nationalId)) return setErr(v.errTckn);
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
      setErr(e?.message ?? v.errSend);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section id="fatura" className="mt-8 scroll-mt-24 rounded-card border border-line bg-white p-5">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-bold text-brand">{v.title}</h2>
          <p className="mt-0.5 text-xs text-ink-soft">{v.sub}</p>
        </div>
        {!open && (
          <button onClick={() => setOpen(true)} className="btn-outline shrink-0 text-sm">
            {existing ? v.edit : v.request}
          </button>
        )}
      </div>

      {status && (
        <p className="mt-3 rounded-card border border-emerald-200 bg-emerald-50 px-3.5 py-2 text-sm text-emerald-800">
          {v.status[status]}
        </p>
      )}

      {done && (
        <p className="mt-3 rounded-card border border-emerald-200 bg-emerald-50 px-3.5 py-2 text-sm font-semibold text-emerald-800">
          {done === 'updated' ? v.updated : v.created}
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
                {t === 'bireysel' ? v.individual : v.corporate}
              </button>
            ))}
          </div>

          {type === 'kurumsal' ? (
            <div className="grid gap-2 sm:grid-cols-2">
              <input className="field sm:col-span-2" placeholder={v.companyName} value={companyName} onChange={(e) => setCompanyName(e.target.value)} />
              {!isDe && <input className="field" placeholder={v.taxOffice} value={taxOffice} onChange={(e) => setTaxOffice(e.target.value)} />}
              <input className={`field ${isDe ? 'sm:col-span-2' : ''}`} placeholder={v.taxNumber} inputMode={isDe ? undefined : 'numeric'} maxLength={isDe ? 40 : 10} value={taxNumber} onChange={(e) => setTaxNumber(isDe ? e.target.value : digits(e.target.value).slice(0, 10))} />
            </div>
          ) : (
            <div className="grid gap-2 sm:grid-cols-2">
              <input className={`field ${isDe ? 'sm:col-span-2' : ''}`} placeholder={v.fullName} value={fullName} onChange={(e) => setFullName(e.target.value)} />
              {!isDe && <input className="field" placeholder={v.nationalId} inputMode="numeric" maxLength={11} value={nationalId} onChange={(e) => setNationalId(digits(e.target.value).slice(0, 11))} />}
            </div>
          )}

          <textarea className="field min-h-[70px] w-full" placeholder={v.address} value={address} onChange={(e) => setAddress(e.target.value)} />
          <input className="field w-full" type="email" placeholder={v.email} value={invoiceEmail} onChange={(e) => setInvoiceEmail(e.target.value)} />

          {err && <p className="form-error">{err}</p>}

          <div className="flex items-center gap-2">
            <button type="submit" disabled={busy} className="btn-primary disabled:opacity-60">
              {busy ? v.sending : existing ? v.update : v.request}
            </button>
            <button type="button" onClick={() => setOpen(false)} className="btn-ghost text-sm">{v.close}</button>
          </div>
          <p className="text-[11px] text-ink-muted">{v.foot}</p>
        </form>
      )}
    </section>
  );
}
