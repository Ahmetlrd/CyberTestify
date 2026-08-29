import { COMPANY } from '../lib/company';
import { getRegion } from '../config/regions';

/**
 * (iyzico/mevzuat) Siparise OZEL Mesafeli Satis Sozlesmesi — checkout'ta, o siparisin
 * gercek hizmet adi + KDV DAHIL fiyati + tarihi ile DINAMIK render edilir. /legal/mesafeli-satis
 * genel/statik referanstir; bu ise "bu siparise ozel" versiyondur.
 *
 * (Çok-bölge) Metin dile göre: /tr Türk hukuku + Mesafeli Sözleşmeler Yön., /de deutsches Recht + § 356 BGB,
 * /en UK Consumer Contracts Regulations 2013. Cayma linki her bölgenin KENDİ hukuki sayfasına gider.
 */
const C = {
  tr: {
    title: 'Mesafeli Satış Sözleşmesi — Bu Siparişe Özel',
    sellerLabel: 'SATICI:', buyerLabel: 'ALICI:',
    buyerText: 'Sipariş sırasında oturum açan hesap sahibi (“Tüketici”).',
    serviceLabel: 'SÖZLEŞME KONUSU HİZMET:', serviceSuffix: '(dijital / SaaS güvenlik değerlendirme hizmeti).',
    totalLabel: 'TOPLAM BEDEL:', vat: '(KDV Dahildir)',
    payLabel: 'ÖDEME ŞEKLİ:', payValue: 'Kredi/banka kartı (iyzico sanal POS)',
    dateLabel: 'SÖZLEŞME TARİHİ:',
    perfLabel: 'İFA:',
    perfText: 'Ödeme onayının ardından hizmet, Tüketici’nin açık onayıyla ANINDA ifa edilmeye başlanır (tarama/rapor üretimi başlar). Rapor hazır olduğunda Tüketici’nin panelinde erişime açılır; tek kullanımlık erişim kodu e-posta ile iletilir.',
    withdrawLabel: 'CAYMA HAKKI:',
    withdrawText: 'Hizmet dijital olarak anında ifa edildiğinden, Mesafeli Sözleşmeler Yönetmeliği md. 15/ğ uyarınca ifasına başlandıktan sonra cayma hakkı KULLANILAMAZ. Ayrıntı için ',
    withdrawHref: '/tr/legal/iptal-iade', withdrawLink: 'İptal/İade Koşulları',
    declLabel: 'BEYAN:',
    declText: 'Tüketici, tarama talep ettiği alan adının münhasır sahibi veya yasal yetkili temsilcisi olduğunu; yetkisi dışındaki hiçbir hedefe tarama talep etmeyeceğini kabul ve taahhüt eder.',
    disputeLabel: 'UYUŞMAZLIK:',
    disputeText: 'Türk hukuku uygulanır; parasal sınırlara göre Tüketici Hakem Heyetleri veya Tüketici Mahkemeleri yetkilidir. Tüketici, sipariş ekranında bu sözleşmeyi onayladığında sözleşme kurulur.',
    footer: 'Bu sözleşmenin bir örneği, onayınızla birlikte kalıcı veri saklayıcısı (e-posta) ile tarafınıza iletilir.',
    locale: 'tr-TR',
  },
  de: {
    title: 'Fernabsatzvertrag — für diese Bestellung',
    sellerLabel: 'VERKÄUFER:', buyerLabel: 'KÄUFER:',
    buyerText: 'Der bei der Bestellung angemeldete Kontoinhaber („Verbraucher“).',
    serviceLabel: 'VERTRAGSGEGENSTAND:', serviceSuffix: '(digitaler / SaaS-Sicherheitsbewertungsdienst).',
    totalLabel: 'GESAMTBETRAG:', vat: '(inkl. MwSt.)',
    payLabel: 'ZAHLUNGSART:', payValue: 'Kreditkarte',
    dateLabel: 'VERTRAGSDATUM:',
    perfLabel: 'ERFÜLLUNG:',
    perfText: 'Nach der Zahlungsbestätigung beginnt die Erbringung der Dienstleistung mit der ausdrücklichen Zustimmung des Verbrauchers SOFORT (Scan/Berichterstellung startet). Sobald der Bericht fertig ist, wird er im Dashboard des Verbrauchers freigeschaltet; ein Einmal-Zugangscode wird per E-Mail zugestellt.',
    withdrawLabel: 'WIDERRUFSRECHT:',
    withdrawText: 'Da die Dienstleistung digital und sofort erbracht wird, erlischt das Widerrufsrecht gemäß § 356 Abs. 5 BGB, sobald mit der Ausführung mit Ihrer ausdrücklichen Zustimmung begonnen wurde. Einzelheiten in der ',
    withdrawHref: '/de/legal/widerruf', withdrawLink: 'Widerrufsbelehrung',
    declLabel: 'ERKLÄRUNG:',
    declText: 'Der Verbraucher erklärt und garantiert, dass er der alleinige Eigentümer oder der gesetzlich bevollmächtigte Vertreter der zu scannenden Domain ist und keine Scans für Ziele außerhalb seiner Berechtigung anfordert.',
    disputeLabel: 'STREITIGKEITEN:',
    disputeText: 'Es gilt deutsches Recht; zuständig sind die gesetzlichen Verbrauchergerichte. Der Vertrag kommt zustande, wenn der Verbraucher diesen Vertrag im Bestellbildschirm bestätigt.',
    footer: 'Eine Kopie dieses Vertrags wird Ihnen mit Ihrer Bestätigung auf einem dauerhaften Datenträger (E-Mail) zugesandt.',
    locale: 'de-DE',
  },
  en: {
    title: 'Distance Sales Contract — For This Order',
    sellerLabel: 'SELLER:', buyerLabel: 'BUYER:',
    buyerText: 'The account holder logged in at the time of the order (“Consumer”).',
    serviceLabel: 'CONTRACT SERVICE:', serviceSuffix: '(digital / SaaS security assessment service).',
    totalLabel: 'TOTAL AMOUNT:', vat: '(VAT included)',
    payLabel: 'PAYMENT METHOD:', payValue: 'Credit card',
    dateLabel: 'CONTRACT DATE:',
    perfLabel: 'PERFORMANCE:',
    perfText: 'After payment confirmation, performance of the service begins IMMEDIATELY with the Consumer’s express consent (scan/report generation starts). When the report is ready, it is made available in the Consumer’s dashboard; a one-time access code is delivered by email.',
    withdrawLabel: 'RIGHT TO CANCEL:',
    withdrawText: 'As the service is digital and performed immediately, the right to cancel is lost once performance has begun with your express consent, under the Consumer Contracts (Information, Cancellation and Additional Charges) Regulations 2013. For details see the ',
    withdrawHref: '/en/legal/cancellation', withdrawLink: 'Cancellation Terms',
    declLabel: 'DECLARATION:',
    declText: 'The Consumer represents and warrants that they are the exclusive owner or legally authorised representative of the domain to be scanned, and will not request scans against any target outside their authority.',
    disputeLabel: 'DISPUTES:',
    disputeText: 'The laws of England and Wales apply; the competent consumer courts have jurisdiction. The contract is formed when the Consumer confirms this contract on the order screen.',
    footer: 'A copy of this contract is sent to you on a durable medium (email) upon your confirmation.',
    locale: 'en-GB',
  },
} as const;

export function DynamicContract({
  serviceName,
  priceLabel,
  region,
}: {
  serviceName: string;
  priceLabel: string; // formatlanmis, "KDV Dahil" tutar
  region: string;
}) {
  const rlang = getRegion(region).lang;
  const c = C[rlang === 'de' ? 'de' : rlang === 'en' ? 'en' : 'tr'];
  const today = new Date().toLocaleDateString(c.locale, { day: 'numeric', month: 'long', year: 'numeric' });
  return (
    <div className="mt-3 max-h-72 overflow-y-auto rounded-card border border-line bg-white p-4 text-xs leading-relaxed text-ink-soft">
      <p className="text-sm font-bold text-brand">{c.title}</p>

      <p className="mt-2">
        <strong>{c.sellerLabel}</strong> {COMPANY.brand} — E-posta: {COMPANY.email}.
      </p>
      <p className="mt-1">
        <strong>{c.buyerLabel}</strong> {c.buyerText}
      </p>

      <p className="mt-2">
        <strong>{c.serviceLabel}</strong> {serviceName} {c.serviceSuffix}
      </p>
      <p className="mt-1">
        <strong>{c.totalLabel}</strong> {priceLabel} <strong>{c.vat}</strong>.{' '}
        <strong>{c.payLabel}</strong> {c.payValue}.{' '}
        <strong>{c.dateLabel}</strong> {today}.
      </p>

      <p className="mt-2">
        <strong>{c.perfLabel}</strong> {c.perfText}
      </p>
      <p className="mt-1">
        <strong>{c.withdrawLabel}</strong> {c.withdrawText}
        <a href={c.withdrawHref} target="_blank" className="text-accent-600 underline">
          {c.withdrawLink}
        </a>
        .
      </p>
      <p className="mt-1">
        <strong>{c.declLabel}</strong> {c.declText}
      </p>
      <p className="mt-1">
        <strong>{c.disputeLabel}</strong> {c.disputeText}
      </p>
      <p className="mt-2 text-ink-muted">{c.footer}</p>
    </div>
  );
}
