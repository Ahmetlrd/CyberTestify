// DRAFT — must be reviewed by a qualified UK solicitor before publication. Business details are placeholders.
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { EnLegalArticle } from '../../../../components/EnLegalArticle';

export const metadata: Metadata = {
  title: 'Terms & Conditions — CyberTestify',
  description: 'Terms and conditions for the use of CyberTestify under the law of England and Wales.',
  alternates: { canonical: '/en/legal/terms' },
  robots: { index: false, follow: true },
};

// (United Kingdom) Terms & Conditions — draft under UK consumer law. /en only.
export default function TermsPage({ params }: { params: { region: string } }) {
  if (params.region !== 'en') notFound();
  return (
    <EnLegalArticle title="Terms & Conditions">
      <h2>1. Scope and provider</h2>
      <p>
        These Terms and Conditions apply to all contracts concluded through CyberTestify for the use
        of the security pre-assessment service. The provider is the entity identified in our{' '}
        <a href="/en/legal/business-info">Business Information</a> page.
      </p>

      <h2>2. Description of the service</h2>
      <p>
        CyberTestify provides an AI-assisted, automated security <em>pre-assessment</em> for a domain
        that you have verified via DNS. The result is a technical report. The service is an
        experimental, automated pre-assessment and is <strong>not</strong> a formal penetration test,
        audit or certification, and does not replace one. No particular number of findings or level of
        completeness is guaranteed for the autonomous or deterministic procedures.
      </p>

      <h2>3. Formation of contract</h2>
      <p>
        The presentation of packages does not constitute a legally binding offer. By submitting your
        order you make a binding offer; the contract is formed when we confirm it or make the service
        available.
      </p>

      <h2>4. Authorisation requirement</h2>
      <p>
        You may only order a scan for domains or systems that you own or for which you hold express
        written authorisation. Verification of domain ownership is a precondition for carrying out the
        scan. You are responsible for ensuring that your instruction does not breach any third-party
        rights or applicable law.
      </p>

      <h2>5. Acceptable use</h2>
      <p>
        You must not use the service to scan targets you are not authorised to test, to disrupt or
        overload third-party systems, or for any unlawful purpose. We may suspend or refuse a scan
        where we reasonably believe these terms are being breached.
      </p>

      <h2>6. Pricing and payment</h2>
      <p>
        The prices stated at the time of your order apply, in pounds sterling (GBP), including VAT
        where applicable. Payment is processed through our payment provider (iyzico). A receipt or
        invoice is provided electronically.
      </p>

      <h2>7. Delivery of the report</h2>
      <p>
        The report is provided electronically after the scan is completed, in encrypted form and with
        a one-time access code. No delivery is made on a physical medium.
      </p>

      <h2>8. Cancellation</h2>
      <p>
        Consumers generally have a right to cancel (see our{' '}
        <a href="/en/legal/cancellation">Cancellation Rights</a>). Because the service is a digital
        service performed immediately, this right can be lost once performance has begun with your
        express consent and acknowledgement, as explained on that page.
      </p>

      <h2>9. Liability</h2>
      <p>
        Nothing in these terms excludes or limits our liability where it would be unlawful to do so,
        including liability for death or personal injury caused by negligence, for fraud or fraudulent
        misrepresentation, or for any other liability that cannot lawfully be excluded or limited.
        Where our liability is not so restricted, we are not liable for losses that were not
        reasonably foreseeable, that arise from your failure to secure your own systems, or that arise
        from circumstances outside our reasonable control. The service delivers a pre-assessment only;
        remediating any vulnerabilities and securing your systems remains your responsibility. If you
        are a consumer, your statutory rights are not affected.
      </p>

      <h2>10. Governing law and jurisdiction</h2>
      <p>
        These terms are governed by the law of England and Wales, and the courts of England and Wales
        have jurisdiction. If you are a consumer resident elsewhere in the United Kingdom, you may also
        bring proceedings in your local courts, and mandatory consumer-protection rules of your place
        of residence are not affected.
      </p>
    </EnLegalArticle>
  );
}
