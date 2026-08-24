// DRAFT — must be reviewed by a qualified UK solicitor before publication. Business details are placeholders.
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { EnLegalArticle } from '../../../../components/EnLegalArticle';

export const metadata: Metadata = {
  title: 'Privacy Policy — CyberTestify',
  description: 'How personal data is processed under the UK GDPR and the Data Protection Act 2018.',
  alternates: { canonical: '/en/legal/privacy' },
  robots: { index: false, follow: true },
};

// (United Kingdom) Privacy Policy — written for the UK regime (UK GDPR + DPA 2018), not a translation. /en only.
export default function PrivacyPage({ params }: { params: { region: string } }) {
  if (params.region !== 'en') notFound();
  return (
    <EnLegalArticle title="Privacy Policy">
      <p>
        This Privacy Policy explains how personal data is processed when you use CyberTestify, in
        accordance with the UK General Data Protection Regulation (UK GDPR) and the Data Protection
        Act 2018.
      </p>

      <h2>1. Data controller</h2>
      <p>
        {/* PLACEHOLDER — real controller details are entered by the operator (not invented). */}
        The data controller is the service provider identified in our{' '}
        <a href="/en/legal/business-info">Business Information</a> page.
        {' '}[Controller name and contact address to be provided. Contact for data protection
        matters: support@cybertestify.com.]
      </p>

      <h2>2. Personal data we process</h2>
      <ul>
        <li><strong>Account data</strong> — your account email address and related sign-in details, to provide the service.</li>
        <li><strong>Scan target domains</strong> — the domain(s) you verify and submit for assessment, to carry out the security scan and produce your report.</li>
        <li><strong>Payment metadata</strong> — order and payment status and related transaction references (card details are handled by our payment provider, not stored by us).</li>
        <li><strong>Server and log data</strong> — IP address, timestamps and technical access data, for secure operation and abuse prevention.</li>
        <li><strong>Consent records</strong> — time, IP and text version, to evidence consents you have given.</li>
      </ul>

      <h2>3. Lawful bases for processing</h2>
      <p>We rely on the following lawful bases under Article 6 of the UK GDPR:</p>
      <ul>
        <li><strong>Performance of a contract</strong> — to provide the scan and deliver your report, and to take steps at your request before entering into a contract.</li>
        <li><strong>Legitimate interests</strong> — for secure operation, abuse prevention and improving our service, where these interests are not overridden by your rights.</li>
        <li><strong>Consent</strong> — where separately requested (for example, certain optional processing); you may withdraw consent at any time.</li>
        <li><strong>Legal obligation</strong> — where processing is required to comply with the law (for example, accounting and tax record-keeping).</li>
      </ul>

      <h2>4. Scope lock and masking of personal data</h2>
      <p>
        A scan can technically only reach the domain you have verified (scope lock). Personal data
        encountered during a scan is structurally masked before being passed to any AI components, in
        order to minimise the disclosure of personal data (data minimisation).
      </p>

      <h2>5. Recipients and processors</h2>
      <p>
        To deliver the service we use carefully selected providers (hosting, payment processing,
        email delivery and AI processing). These act as our processors under written contracts that
        comply with the UK GDPR.
      </p>

      <h2>6. International transfers</h2>
      <p>
        Some processing steps (for example, certain AI processing) may involve transferring personal
        data to providers located outside the United Kingdom. Where this occurs, we rely on
        appropriate safeguards recognised under the UK GDPR — such as UK adequacy regulations or the
        International Data Transfer Agreement (IDTA) / the UK Addendum to the EU Standard Contractual
        Clauses — and, where required, your explicit consent. Personal data is masked beforehand where
        practicable (see section 4).
      </p>

      <h2>7. Retention</h2>
      <p>
        Personal data is kept only for as long as necessary for the purposes described above or to
        meet legal retention requirements. [Specific retention periods to be provided by the
        operator.] Reports are provided in encrypted form and deleted after the defined period.
      </p>

      <h2>8. Security measures</h2>
      <p>
        We implement appropriate technical and organisational measures to protect personal data,
        including encryption of reports, access controls, structural masking of personal data before
        AI processing, and scope restrictions that limit scanning to verified domains.
      </p>

      <h2>9. Your rights under the UK GDPR</h2>
      <p>Subject to the conditions in the legislation, you have the right to:</p>
      <ul>
        <li>access your personal data;</li>
        <li>rectification of inaccurate data;</li>
        <li>erasure of your data;</li>
        <li>restriction of processing;</li>
        <li>data portability;</li>
        <li>object to processing, including processing based on legitimate interests;</li>
        <li>withdraw consent at any time, where processing is based on consent.</li>
      </ul>
      <p>
        To exercise your rights, please contact support@cybertestify.com.
      </p>

      <h2>10. Complaints to the supervisory authority</h2>
      <p>
        If you are concerned about how your personal data is handled, you have the right to lodge a
        complaint with the Information Commissioner's Office (ICO), the UK supervisory authority, at{' '}
        <a href="https://ico.org.uk/" target="_blank" rel="noopener noreferrer">https://ico.org.uk/</a>.
        We would, however, appreciate the chance to address your concerns first.
      </p>

      <h2>11. Cookies</h2>
      <p>
        We use only strictly necessary cookies required to operate the service (for example, session
        and region selection). [Further details of any analytics/marketing cookies will be added if
        and when they are used, with prior consent where required.]
      </p>
    </EnLegalArticle>
  );
}
