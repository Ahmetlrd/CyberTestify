// DRAFT — kullanıcının sağladığı metin BİREBİR yerleştirildi (yeniden yazılmadı/genişletilmedi).
// Yayına çıkmadan önce nitelikli bir hukuk danışmanınca gözden geçirilmelidir.
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { EnLegalArticle } from '../../../../components/EnLegalArticle';

export const metadata: Metadata = {
  title: 'Terms &amp; Conditions — CyberTestify',
  description: 'Terms and conditions for the CyberTestify automated security pre-assessment service.',
  alternates: { canonical: '/en/legal/terms' },
  robots: { index: true, follow: true },
};

// (United Kingdom) /en only — other regions do not have this slug.
export default function Page({ params }: { params: { region: string } }) {
  if (params.region !== 'en') notFound();
  return (
    <EnLegalArticle title="Terms &amp; Conditions">

      <h2>1. About the service</h2>
      <p>
        CyberTestify provides automated security pre-assessment and scanning services for websites
        and web applications. The service is designed to identify potential security issues using
        automated and largely non-intrusive methods.
      </p>
      <p>
        <strong>Important:</strong> CyberTestify is not a formal penetration test, security audit, or
        certification (including but not limited to ASV, QSA, ISO 27001 certification, or
        CREST-accredited testing). Reports are generated with AI assistance and should not be relied
        upon as the sole basis for security decisions without independent verification.
      </p>

      <h2>2. Eligibility and account</h2>
      <p>
        You must be at least 18 years old and able to enter into a binding contract. You are
        responsible for maintaining the confidentiality of your account credentials.
      </p>

      <h2>3. Domain ownership and authorisation</h2>
      <p>
        You may only submit domains or assets that you own or for which you have explicit
        authorisation to test. By submitting a target you confirm that you have the legal right to
        have it scanned. We reserve the right to refuse or terminate any scan where ownership or
        authorisation cannot be verified.
      </p>

      <h2>4. Scope of the service</h2>
      <p>
        Each package has a defined scope (described on the pricing page). Scans are performed on a
        best-effort basis. Results depend on the target’s configuration, technology and
        accessibility. Some checks may be reported as “out of scope” or “not tested” when the
        target’s structure does not allow them. This is normal and does not constitute a failure of
        the service.
      </p>
      <p>
        We follow a “prove, don’t exploit” approach. We do not perform destructive testing, data
        modification, or real exploitation.
      </p>

      <h2>5. Reports</h2>
      <p>
        Reports are delivered in encrypted form and are accessible with a unique code. Reports are
        confidential and intended only for the customer who ordered them.
      </p>

      <h2>6. Fees and payment</h2>
      <p>
        Prices are as displayed at the time of purchase (including applicable taxes). Payment is
        required before the scan starts. All fees are non-refundable once the scan has begun, except
        where required by applicable law.
      </p>

      <h2>7. Acceptable use</h2>
      <p>
        You must not use the service to scan systems without authorisation, to attack third parties,
        or for any unlawful purpose. We may suspend or terminate access in case of abuse.
      </p>

      <h2>8. Limitation of liability</h2>
      <p>To the maximum extent permitted by law:</p>
      <ul>
        <li>The service is provided “as is”.</li>
        <li>We do not warrant that the scan will detect every possible vulnerability.</li>
        <li>We are not liable for indirect, incidental, or consequential damages, loss of profits, or loss of data.</li>
        <li>Our total liability for any claim arising out of the service is limited to the amount you paid for the specific scan giving rise to the claim.</li>
      </ul>
      <p>
        Nothing in these terms excludes or limits liability for death or personal injury caused by
        negligence, fraud, or any other liability that cannot be excluded under applicable law.
      </p>

      <h2>9. Intellectual property</h2>
      <p>
        All rights in the CyberTestify platform, methodology and report templates remain with us. You
        receive a limited licence to use the report for your internal security purposes.
      </p>

      <h2>10. Governing law</h2>
      <p>
        These terms are governed by the laws of England and Wales. Courts of England and Wales shall
        have exclusive jurisdiction, without prejudice to any mandatory consumer protection rights
        you may have in your country of residence.
      </p>

      <h2>11. Changes</h2>
      <p>
        We may update these terms from time to time. The version published on the website at the
        time of purchase applies to that order.
      </p>

      <h2>12. Contact</h2>
      <p><a href="mailto:support@cybertestify.com">support@cybertestify.com</a></p>
    </EnLegalArticle>
  );
}
