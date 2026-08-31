// DRAFT — kullanıcının sağladığı metin BİREBİR yerleştirildi (yeniden yazılmadı/genişletilmedi).
// Yayına çıkmadan önce nitelikli bir hukuk danışmanınca gözden geçirilmelidir.
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { EnLegalArticle } from '../../../../components/EnLegalArticle';

export const metadata: Metadata = {
  title: 'Privacy Policy — CyberTestify',
  description: 'How CyberTestify collects, uses and protects personal data under UK GDPR and EU GDPR.',
  alternates: { canonical: '/en/legal/privacy' },
  robots: { index: true, follow: true },
};

// (United Kingdom) /en only — other regions do not have this slug.
export default function Page({ params }: { params: { region: string } }) {
  if (params.region !== 'en') notFound();
  return (
    <EnLegalArticle title="Privacy Policy">

      <h2>1. Who we are</h2>
      <p>
        CyberTestify (“we”, “us”) is an automated security pre-assessment service. We process
        personal data in accordance with the UK GDPR and the Data Protection Act 2018 when offering
        services to customers in the United Kingdom, and with the EU GDPR when offering services to
        customers in the European Union.
      </p>

      <h2>2. What data we collect</h2>
      <p>We may collect and process:</p>
      <ul>
        <li>Email address and name (when you create an account or place an order)</li>
        <li>Domain name / URL you submit for scanning</li>
        <li>Payment information (processed by our payment provider; we do not store full card details)</li>
        <li>Technical data (IP address, browser type, device information) for security and fraud prevention</li>
        <li>Scan-related data strictly limited to the target you have authorised</li>
      </ul>

      <h2>3. How we use your data</h2>
      <p>We use the data to:</p>
      <ul>
        <li>Provide the security scan and deliver the encrypted report</li>
        <li>Verify domain ownership</li>
        <li>Process payments and prevent fraud</li>
        <li>Communicate with you about your order</li>
        <li>Improve and secure our service</li>
      </ul>
      <p>We do not sell your personal data.</p>

      <h2>4. Legal bases</h2>
      <ul>
        <li>Contract performance (to deliver the service you ordered)</li>
        <li>Legitimate interests (security, fraud prevention, service improvement)</li>
        <li>Legal obligation where applicable</li>
      </ul>

      <h2>5. Data retention</h2>
      <ul>
        <li>Account and order data: kept for as long as your account is active and for a reasonable period afterwards for legal and accounting purposes</li>
        <li>Scan data and reports: retained only for the time necessary to deliver the report and for a limited period for support; reports are end-to-end encrypted</li>
        <li>We apply data minimisation and do not keep data longer than needed</li>
      </ul>

      <h2>6. Sharing of data</h2>
      <p>We may share data with:</p>
      <ul>
        <li>Payment processors</li>
        <li>Infrastructure and email service providers (under data processing agreements)</li>
        <li>Authorities if required by law</li>
      </ul>
      <p>We do not share data with third parties for their own marketing.</p>

      <h2>7. International transfers</h2>
      <p>
        Data may be processed outside the UK/EU. Where this happens we use appropriate safeguards
        (such as Standard Contractual Clauses) where required.
      </p>

      <h2>8. Your rights</h2>
      <p>Under UK GDPR / EU GDPR you have the right to:</p>
      <ul>
        <li>Access your data</li>
        <li>Rectification</li>
        <li>Erasure (in certain circumstances)</li>
        <li>Restriction of processing</li>
        <li>Data portability</li>
        <li>Object to processing</li>
        <li>Lodge a complaint with the ICO (UK) or your local supervisory authority</li>
      </ul>
      <p>To exercise these rights, contact: <a href="mailto:support@cybertestify.com">support@cybertestify.com</a></p>

      <h2>9. Security</h2>
      <p>
        We use technical and organisational measures including encryption of reports, access
        controls and isolation of scanning environments.
      </p>

      <h2>10. Contact</h2>
      <p>For privacy-related requests: <a href="mailto:support@cybertestify.com">support@cybertestify.com</a></p>
    </EnLegalArticle>
  );
}
