import { COMPANY } from '../../../lib/company';
import { notFound } from 'next/navigation';
import { VISIBLE_REGION_CODES, isRegionCode, getRegion } from '../../../config/regions';

// (Çok-bölge) Bölge-bağımsız kök sayfa; dili region cookie'sinden alır (tr | de). us/ae (en) → tr'ye
// düşer (görünmez). /de bağlamında Türkçe SIZMAZ.
const T = {
  tr: {
    title: 'İletişim',
    intro: 'Sorularınız, destek talepleriniz ve sözleşmesel bildirimler için bize aşağıdaki kanallardan ulaşabilirsiniz.',
    emailLabel: 'E-posta',
    note: 'Destek taleplerine genellikle 1 iş günü içinde dönüş yapılır. Ödeme ve faturalandırmaya ilişkin sorularınız için de aynı e-posta adresini kullanabilirsiniz.',
    metaTitle: 'İletişim — CyberTestify',
    metaDesc: 'CyberTestify ile iletişime geçin — destek, sorular ve kurumsal talepler için.',
    bizLabel: 'İşletme Bilgileri', bizOperator: 'Bu hizmet aşağıdaki işletme tarafından sunulmaktadır:',
    bizRegistered: 'Türkiye’de kayıtlı',
  },
  de: {
    title: 'Kontakt',
    intro: 'Für Fragen, Support-Anfragen und vertragliche Mitteilungen erreichen Sie uns über die folgenden Kanäle.',
    emailLabel: 'E-Mail',
    note: 'Support-Anfragen werden in der Regel innerhalb von 1 Werktag beantwortet. Für Fragen zu Zahlung und Rechnungsstellung können Sie dieselbe E-Mail-Adresse verwenden.',
    metaTitle: 'Kontakt — CyberTestify',
    metaDesc: 'Kontaktieren Sie CyberTestify — für Support, Fragen und Unternehmensanfragen.',
    bizLabel: 'Angaben zum Anbieter', bizOperator: 'Dieser Dienst wird angeboten von:',
    bizRegistered: 'Registriert in der Türkei',
  },
  en: {
    title: 'Contact',
    intro: 'For questions, support requests and contractual notices, you can reach us through the channels below.',
    emailLabel: 'Email',
    note: 'Support requests are usually answered within 1 business day. You can use the same email address for questions about payment and invoicing.',
    metaTitle: 'Contact — CyberTestify',
    metaDesc: 'Get in touch with CyberTestify — for support, questions and business enquiries.',
    bizLabel: 'Business Information', bizOperator: 'This service is provided by:',
    bizRegistered: 'Registered in Turkey',
  },
} as const;

// (URL TUTARLILIGI) Dil artik COOKIE'den degil URL bolgesinden gelir; sayfa /{bolge}/iletisim altinda.
const SITE_URL = 'https://cybertestify.com';

function pick(regionCode: string) {
  const region = getRegion(regionCode);
  const lang = region.lang === 'de' ? 'de' : region.lang === 'en' ? 'en' : 'tr';
  return T[lang];
}

export function generateStaticParams() {
  return VISIBLE_REGION_CODES.map((region) => ({ region }));
}

export function generateMetadata({ params }: { params: { region: string } }) {
  const t = pick(params.region);
  return {
    title: t.metaTitle,
    description: t.metaDesc,
    alternates: {
      canonical: `${SITE_URL}/${params.region}/iletisim`,
      languages: { tr: `${SITE_URL}/tr/iletisim`, de: `${SITE_URL}/de/iletisim`, en: `${SITE_URL}/en/iletisim`, 'x-default': `${SITE_URL}/tr/iletisim` },
    },
    openGraph: { type: 'website' as const, siteName: 'CyberTestify', url: `${SITE_URL}/${params.region}/iletisim`, title: t.metaTitle, description: t.metaDesc },
  };
}

export default function Page({ params }: { params: { region: string } }) {
  if (!isRegionCode(params.region)) notFound();
  const t = pick(params.region);
  return (
    <main className="container-page max-w-2xl py-14">
      <h1 className="text-3xl font-extrabold text-brand">{t.title}</h1>
      <p className="mt-3 text-ink-soft">{t.intro}</p>

      <div className="mt-8 space-y-5 rounded-card border border-line bg-brand-50/40 p-6 text-sm leading-relaxed text-ink-soft">
        {/* (İŞLETME BİLGİSİ) /de Impressum ve /en business-info ile AYNI bilgi — TR'de de görünsün.
            PLACEHOLDER: gerçek tescilli unvan + vergi/MERSIS no + adres OPERATÖR tarafından
            doldurulmalı (uydurulmadı; lib/company.ts'te bu alanlar bilinçli olarak yok). */}
        <div>
          <div className="text-xs font-bold uppercase tracking-wide text-brand-500">{t.bizLabel}</div>
          <p className="mt-1">{t.bizOperator}</p>
          <p className="mt-1.5">
            <strong className="text-ink">CyberTestify co</strong>
            <br />
            {t.bizRegistered}
          </p>
        </div>

        <div className="border-t border-line pt-4">
          <div className="text-xs font-bold uppercase tracking-wide text-brand-500">{t.emailLabel}</div>
          <a href={`mailto:${COMPANY.email}`} className="text-accent-600 underline">
            {COMPANY.email}
          </a>
        </div>
      </div>

      <p className="mt-6 text-xs text-ink-muted">{t.note}</p>
    </main>
  );
}
