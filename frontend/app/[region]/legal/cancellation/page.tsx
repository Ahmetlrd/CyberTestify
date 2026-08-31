// DRAFT — kullanıcının sağladığı metin BİREBİR yerleştirildi (yeniden yazılmadı/genişletilmedi).
// Yayına çıkmadan önce nitelikli bir hukuk danışmanınca gözden geçirilmelidir.
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { EnLegalArticle } from '../../../../components/EnLegalArticle';

export const metadata: Metadata = {
  title: 'Cancellation &amp; Refund Policy — CyberTestify',
  description: 'Cancellation and refund policy for CyberTestify under the Consumer Contracts Regulations 2013.',
  alternates: { canonical: '/en/legal/cancellation' },
  robots: { index: true, follow: true },
};

// (United Kingdom) /en only — other regions do not have this slug.
export default function Page({ params }: { params: { region: string } }) {
  if (params.region !== 'en') notFound();
  return (
    <EnLegalArticle title="Cancellation &amp; Refund Policy">
      <p><em>Last updated: 31 August 2026</em></p>

      <h2>1. Digital service</h2>
      <p>
        CyberTestify provides a digital service (automated security scanning and reporting). Once you
        have placed an order and the scan process has started, the service has begun.
      </p>

      <h2>2. Right of withdrawal (UK &amp; EU consumers)</h2>
      <p>
        Under the Consumer Contracts Regulations 2013 (UK) and equivalent EU rules, you normally have
        a 14-day right to cancel a distance contract.
      </p>
      <p>
        However, you lose the right to cancel once the digital service has started with your prior
        express consent and acknowledgement that you will lose the right to cancel.
      </p>
      <p>By purchasing a scan and confirming the order you:</p>
      <ul>
        <li>Request that we start the scan immediately, and</li>
        <li>Acknowledge that you lose the right to cancel once the scan has started.</li>
      </ul>

      <h2>3. Refunds</h2>
      <ul>
        <li>Before the scan has started: you may request a full refund by contacting <a href="mailto:support@cybertestify.com">support@cybertestify.com</a>.</li>
        <li>After the scan has started: no refund is available, except where required by mandatory law or in cases of clear service failure on our part.</li>
      </ul>

      <h2>4. Service failure</h2>
      <p>
        If we are unable to deliver a report due to a technical failure on our side, you will be
        entitled to a full refund or a free re-run at our discretion.
      </p>

      <h2>5. How to contact us</h2>
      <p>
        For cancellation or refund requests:{' '}
        <a href="mailto:support@cybertestify.com">support@cybertestify.com</a><br />
        Please include your order reference.
      </p>

      <h2>6. Governing law</h2>
      <p>This policy is governed by the laws of England and Wales.</p>
    </EnLegalArticle>
  );
}
