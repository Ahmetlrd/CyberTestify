import { COMPANY } from '../lib/company';

/**
 * (iyzico/mevzuat) Siparise OZEL Mesafeli Satis Sozlesmesi — checkout'ta, o siparisin
 * gercek hizmet adi + KDV DAHIL fiyati + tarihi ile DINAMIK render edilir. /legal/mesafeli-satis
 * genel/statik referanstir; bu ise "bu siparise ozel" versiyondur.
 */
export function DynamicContract({
  serviceName,
  priceLabel,
  region,
}: {
  serviceName: string;
  priceLabel: string; // formatlanmis, "KDV Dahil" tutar
  region: string;
}) {
  const today = new Date().toLocaleDateString('tr-TR', { day: 'numeric', month: 'long', year: 'numeric' });
  return (
    <div className="mt-3 max-h-72 overflow-y-auto rounded-card border border-line bg-white p-4 text-xs leading-relaxed text-ink-soft">
      <p className="text-sm font-bold text-brand">Mesafeli Satış Sözleşmesi — Bu Siparişe Özel</p>

      <p className="mt-2">
        <strong>SATICI:</strong> {COMPANY.brand} — E-posta: {COMPANY.email}.
      </p>
      <p className="mt-1">
        <strong>ALICI:</strong> Sipariş sırasında oturum açan hesap sahibi (&quot;Tüketici&quot;).
      </p>

      <p className="mt-2">
        <strong>SÖZLEŞME KONUSU HİZMET:</strong> {serviceName} (dijital / SaaS güvenlik değerlendirme hizmeti).
      </p>
      <p className="mt-1">
        <strong>TOPLAM BEDEL:</strong> {priceLabel} <strong>(KDV Dahildir)</strong>.{' '}
        <strong>ÖDEME ŞEKLİ:</strong> {region === 'tr' ? 'Kredi/banka kartı (iyzico sanal POS)' : 'Kredi kartı'}.{' '}
        <strong>SÖZLEŞME TARİHİ:</strong> {today}.
      </p>

      <p className="mt-2">
        <strong>İFA:</strong> Ödeme onayının ardından hizmet, Tüketici’nin açık onayıyla ANINDA ifa edilmeye
        başlanır (tarama/rapor üretimi başlar). Rapor hazır olduğunda Tüketici’nin panelinde erişime açılır;
        tek kullanımlık erişim kodu e-posta ile iletilir.
      </p>
      <p className="mt-1">
        <strong>CAYMA HAKKI:</strong> Hizmet dijital olarak anında ifa edildiğinden, Mesafeli Sözleşmeler
        Yönetmeliği md. 15/ğ uyarınca ifasına başlandıktan sonra cayma hakkı KULLANILAMAZ. Ayrıntı için{' '}
        <a href="/legal/iptal-iade" target="_blank" className="text-accent-600 underline">
          İptal/İade Koşulları
        </a>
        .
      </p>
      <p className="mt-1">
        <strong>BEYAN:</strong> Tüketici, tarama talep ettiği alan adının münhasır sahibi veya yasal yetkili
        temsilcisi olduğunu; yetkisi dışındaki hiçbir hedefe tarama talep etmeyeceğini kabul ve taahhüt eder.
      </p>
      <p className="mt-1">
        <strong>UYUŞMAZLIK:</strong> Türk hukuku uygulanır; parasal sınırlara göre Tüketici Hakem Heyetleri veya
        Tüketici Mahkemeleri yetkilidir. Tüketici, sipariş ekranında bu sözleşmeyi onayladığında sözleşme kurulur.
      </p>
      <p className="mt-2 text-ink-muted">
        Bu sözleşmenin bir örneği, onayınızla birlikte kalıcı veri saklayıcısı (e-posta) ile tarafınıza iletilir.
      </p>
    </div>
  );
}
