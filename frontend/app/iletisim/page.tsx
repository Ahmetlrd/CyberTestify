import { cookies } from 'next/headers';
import { COMPANY } from '../../lib/company';
import { getRegion } from '../../config/regions';

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
  },
  de: {
    title: 'Kontakt',
    intro: 'Für Fragen, Support-Anfragen und vertragliche Mitteilungen erreichen Sie uns über die folgenden Kanäle.',
    emailLabel: 'E-Mail',
    note: 'Support-Anfragen werden in der Regel innerhalb von 1 Werktag beantwortet. Für Fragen zu Zahlung und Rechnungsstellung können Sie dieselbe E-Mail-Adresse verwenden.',
    metaTitle: 'Kontakt — CyberTestify',
    metaDesc: 'Kontaktieren Sie CyberTestify — für Support, Fragen und Unternehmensanfragen.',
  },
  en: {
    title: 'Contact',
    intro: 'For questions, support requests and contractual notices, you can reach us through the channels below.',
    emailLabel: 'Email',
    note: 'Support requests are usually answered within 1 business day. You can use the same email address for questions about payment and invoicing.',
    metaTitle: 'Contact — CyberTestify',
    metaDesc: 'Get in touch with CyberTestify — for support, questions and business enquiries.',
  },
} as const;

function pick() {
  const region = getRegion(cookies().get('region')?.value);
  const lang = region.lang === 'de' ? 'de' : region.lang === 'en' ? 'en' : 'tr';
  return T[lang];
}

export function generateMetadata() {
  const t = pick();
  return {
    title: t.metaTitle,
    description: t.metaDesc,
    alternates: { canonical: '/iletisim' },
    openGraph: { type: 'website' as const, siteName: 'CyberTestify', url: 'https://cybertestify.com/iletisim', title: t.metaTitle, description: t.metaDesc },
  };
}

export default function Page() {
  const t = pick();
  return (
    <main className="container-page max-w-2xl py-14">
      <h1 className="text-3xl font-extrabold text-brand">{t.title}</h1>
      <p className="mt-3 text-ink-soft">{t.intro}</p>

      <div className="mt-8 space-y-4 rounded-card border border-line bg-brand-50/40 p-6 text-sm leading-relaxed text-ink-soft">
        <div>
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
