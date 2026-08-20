'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { adminApi } from '../../../../lib/adminApi';
import { H1, Table, StatusBadge, fmtDate, card } from '../../../../components/admin/ui';

const money = (minor: number, cur = 'TRY') => `${(minor / 100).toLocaleString('tr-TR')} ${cur === 'TRY' ? '₺' : cur}`;

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section style={{ marginTop: 22 }}>
      <h2 style={{ fontSize: 15, fontWeight: 700, color: '#e2e8f0', margin: '0 0 8px' }}>{title}</h2>
      {children}
    </section>
  );
}

export default function AdminCustomerDetail({ params }: { params: { id: string } }) {
  const [c, setC] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    adminApi.customerDetail(params.id).then(setC).catch((e) => setError(e.message));
  }, [params.id]);

  async function viewReport(orderId: string) {
    setBusy(orderId);
    try {
      const blob = await adminApi.reportPdfBlob(orderId);
      window.open(URL.createObjectURL(blob), '_blank');
    } catch (e) {
      alert((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  if (error) return <><H1>Müşteri</H1><p style={{ color: '#fca5a5' }}>{error}</p></>;
  if (!c) return <><H1>Müşteri</H1><p style={{ color: '#94a3b8' }}>Yükleniyor…</p></>;

  return (
    <>
      <Link href="/admin/customers" style={{ color: '#94a3b8', fontSize: 13 }}>← Müşteriler</Link>
      <H1>{c.email}</H1>
      <div style={{ ...card, display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(160px,1fr))', gap: 12, fontSize: 13, color: '#cbd5e1' }}>
        <div><b style={{ color: '#94a3b8' }}>Ad</b><br />{c.fullName || '—'}</div>
        <div><b style={{ color: '#94a3b8' }}>Kayıt</b><br />{fmtDate(c.createdAt)}</div>
        <div><b style={{ color: '#94a3b8' }}>E-posta doğrulandı</b><br />{c.emailVerified ? 'Evet' : 'Hayır'}</div>
        <div><b style={{ color: '#94a3b8' }}>Google</b><br />{c.hasGoogle ? 'Bağlı' : '—'}</div>
        <div><b style={{ color: '#94a3b8' }}>ToS</b><br />{c.termsAcceptedAt ? `${fmtDate(c.termsAcceptedAt)} (${c.termsVersion || '?'})` : '—'}</div>
      </div>

      <Section title={`Alan adları (${c.domains.length})`}>
        <Table
          columns={['Alan adı', 'Durum', 'Doğrulama', 'Çözülen IP', 'Hosting', 'Kayıt']}
          rows={c.domains.map((d: any) => [
            <b key="h" style={{ color: '#e2e8f0' }}>{d.hostname}</b>,
            <StatusBadge key="s" status={d.status} />,
            d.verifiedAt ? `${d.verificationMethod || ''} ${fmtDate(d.verifiedAt)}` : '—',
            d.resolvedIps || '—', d.hostingType || '—', fmtDate(d.createdAt),
          ])}
        />
      </Section>

      <Section title={`Siparişler (${c.orders.length})`}>
        <Table
          columns={['Hedef', 'Paket', 'Durum', 'Tutar', 'Tarih', 'Akış', 'Rapor']}
          rows={c.orders.map((o: any) => [
            o.domain?.hostname || '—',
            o.package?.displayName || o.package?.key || '—',
            <StatusBadge key="s" status={o.status} />,
            money(o.amountMinorUnit, o.currency),
            fmtDate(o.createdAt),
            o.flow ? `${o.flow.status} · ${o.flow.toolCallCount ?? 0} tc${o.flow.scopeViolationTarget ? ' ⚠kapsam' : ''}` : '—',
            o.report ? (
              <button key="r" onClick={() => viewReport(o.id)} disabled={busy === o.id}
                style={{ padding: '3px 8px', borderRadius: 6, border: '1px solid #334155', background: '#0f172a', color: '#7dd3fc', cursor: 'pointer', fontSize: 12 }}>
                {busy === o.id ? '…' : 'Raporu gör'}
              </button>
            ) : '—',
          ])}
        />
        <p style={{ fontSize: 11, color: '#64748b', marginTop: 6 }}>
          Not: Rapor içeriği müşteri anahtarıyla şifrelidir; yalnız erişim kodu sunucuda saklandığında (dev/mock) admin çözebilir. Gerçek ödeme modunda içerik yalnız müşteride açılır.
        </p>
      </Section>

      <Section title={`Planlı taramalar (${c.scheduledScans.length})`}>
        <Table
          columns={['Alan adı', 'Paket', 'Aralık', 'Kalan', 'Sonraki', 'Aktif', 'Hata']}
          rows={c.scheduledScans.map((s: any) => [
            s.domain?.hostname || '—', s.packageKey, `${s.intervalDays}g`, s.remainingRuns,
            fmtDate(s.nextRunAt), s.active ? 'Evet' : 'Hayır', s.failCount,
          ])}
        />
      </Section>

      <Section title={`Aktif-test rızaları (${c.activeTestConsents.length})`}>
        <Table
          columns={['Sipariş', 'Ad', 'Risk kabul', 'Metin sürümü', 'Tarih']}
          rows={c.activeTestConsents.map((k: any) => [
            k.orderId, k.legalName || '—', k.riskAccepted ? 'Evet' : 'Hayır', k.textVersion || '—', fmtDate(k.createdAt),
          ])}
        />
      </Section>
    </>
  );
}
