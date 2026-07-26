'use client';

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';

export default function PackagesPage() {
  const router = useRouter();
  const domainId = useSearchParams().get('domainId');
  const [packages, setPackages] = useState<
    Array<{ key: string; displayName: string; description: string; priceMinorUnit: number }>
  >([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Uc ayri riza (KVKK/TCK ve tuketici mevzuati geregi ayri ayri alinir).
  const [authConsent, setAuthConsent] = useState(false); // pentest yetkilendirme (TCK 243)
  const [contractConsent, setContractConsent] = useState(false); // MSS + On Bilgilendirme
  const [withdrawalConsent, setWithdrawalConsent] = useState(false); // cayma feragat

  const allConsents = authConsent && contractConsent && withdrawalConsent;

  useEffect(() => {
    if (typeof window !== 'undefined' && !window.localStorage.getItem('token')) {
      router.push('/login');
      return;
    }
    api.listPackages().then(setPackages).catch((err) => setError(err.message));
  }, [router]);

  async function handleSelect(key: string) {
    if (!domainId || busy) return;
    if (!allConsents) {
      setError('Devam etmek için aşağıdaki üç onayın tümünü işaretlemelisiniz.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const res = await api.createOrder(domainId, key, {
        ownershipConfirmed: authConsent,
        distanceContractAccepted: contractConsent,
        withdrawalWaived: withdrawalConsent,
      });
      window.location.href = res.paymentPageUrl;
    } catch (err: any) {
      setError(err.message);
      setBusy(false);
    }
  }

  const box: React.CSSProperties = {
    display: 'flex',
    gap: 10,
    alignItems: 'flex-start',
    background: '#f6f8fa',
    border: '1px solid #d0d7de',
    borderRadius: 8,
    padding: 12,
    marginBottom: 10,
    fontSize: 14,
  };

  return (
    <main>
      <h1>Taramanızı Başlatın</h1>
      {!domainId && (
        <p style={{ color: 'crimson' }}>
          Önce site sahipliğinizi doğrulamalısınız. <a href="/verify">Doğrulamaya git →</a>
        </p>
      )}

      <h3 style={{ marginBottom: 8 }}>Onaylar</h3>
      <label style={box}>
        <input type="checkbox" checked={authConsent} onChange={(e) => setAuthConsent(e.target.checked)} style={{ marginTop: 3 }} />
        <span>
          Bu alan adının <strong>ve bağlı altyapısının</strong> münhasır sahibi olduğumu veya adına
          işlem yapmaya yasal olarak yetkili olduğumu; yalnızca bu alan adı kapsamında, saldırgan
          olmayan pasif bir güvenlik taraması yapılmasına rıza gösterdiğimi beyan ederim. Kapsam dışı
          hiçbir hedefe erişilmeyeceğini anladım.
        </span>
      </label>
      <label style={box}>
        <input type="checkbox" checked={contractConsent} onChange={(e) => setContractConsent(e.target.checked)} style={{ marginTop: 3 }} />
        <span>
          <Link href="/legal/on-bilgilendirme" target="_blank">Ön Bilgilendirme Formu</Link>&apos;nu ve{' '}
          <Link href="/legal/mesafeli-satis" target="_blank">Mesafeli Satış Sözleşmesi</Link>&apos;ni okudum, onaylıyorum.
        </span>
      </label>
      <label style={box}>
        <input type="checkbox" checked={withdrawalConsent} onChange={(e) => setWithdrawalConsent(e.target.checked)} style={{ marginTop: 3 }} />
        <span>
          Satın aldığım hizmetin dijital olarak <strong>anında ifa</strong> edildiğini; açık onayımla
          ifasına hemen başlanacağını ve Mesafeli Sözleşmeler Yönetmeliği md. 15 uyarınca ifaya
          başlanmasıyla <strong>cayma hakkımı kullanamayacağımı</strong> okudum, kabul ediyorum.
        </span>
      </label>

      {error && <p style={{ color: 'crimson' }}>{error}</p>}

      <div style={{ display: 'grid', gap: 16, marginTop: 16 }}>
        {packages.map((p) => (
          <div key={p.key} style={{ border: '1px solid #ddd', borderRadius: 8, padding: 16 }}>
            <h3>{p.displayName}</h3>
            <p>{p.description}</p>
            <p>
              <strong>{(p.priceMinorUnit / 100).toLocaleString('tr-TR')} TRY</strong>{' '}
              <span style={{ fontSize: 12, color: '#57606a' }}>(tüm vergiler dahil)</span>
            </p>
            <button disabled={!domainId || busy || !allConsents} onClick={() => handleSelect(p.key)}>
              {busy ? 'Başlatılıyor…' : 'Taramayı Başlat'}
            </button>
          </div>
        ))}
      </div>
    </main>
  );
}
