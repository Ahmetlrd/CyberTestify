// DRAFT — kullanıcının sağladığı metin BİREBİR yerleştirildi (yeniden yazılmadı/genişletilmedi).
// Yayına çıkmadan önce nitelikli bir hukuk danışmanınca gözden geçirilmelidir.
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { EnLegalArticle } from '../../../../components/EnLegalArticle';

export const metadata: Metadata = {
  title: 'Business Information — CyberTestify',
  description: 'Provider and business information for CyberTestify (UK/EU customers).',
  alternates: { canonical: '/en/legal/business-info' },
  robots: { index: true, follow: true },
};

// (United Kingdom) /en only — other regions do not have this slug.
export default function Page({ params }: { params: { region: string } }) {
  if (params.region !== 'en') notFound();
  return (
    <EnLegalArticle title="Business Information">
      <p>CyberTestify is operated by:</p>

      {/* PLACEHOLDER — GERÇEK şirket unvanı, varsa vergi/şirket numarası ve adres OPERATÖR
          tarafından doldurulmalıdır. Uydurulmadı; kullanıcının verdiği metin aynen korundu. */}
      <p>
        <strong>CyberTestify co</strong><br />
        Registered in Turkey
      </p>

      <h2>Contact</h2>
      <p>Email: <a href="mailto:support@cybertestify.com">support@cybertestify.com</a></p>

      <p>
        This website and the CyberTestify service are provided by the above operator. We sell
        automated security pre-assessment services to customers in the United Kingdom and the
        European Union.
      </p>
      <p>
        For any questions regarding the service, billing or data protection, please contact us at
        the email address above.
      </p>
    </EnLegalArticle>
  );
}
