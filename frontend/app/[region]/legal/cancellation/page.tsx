// DRAFT — must be reviewed by a qualified UK solicitor before publication. Business details are placeholders.
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { EnLegalArticle } from '../../../../components/EnLegalArticle';

export const metadata: Metadata = {
  title: 'Cancellation Rights — CyberTestify',
  description: 'Consumer cancellation rights under the Consumer Contracts Regulations 2013 and the express-consent waiver for digital services.',
  alternates: { canonical: '/en/legal/cancellation' },
  robots: { index: false, follow: true },
};

// (United Kingdom) Cancellation Rights — /en only. The checkout consent flow links here.
export default function CancellationPage({ params }: { params: { region: string } }) {
  if (params.region !== 'en') notFound();
  return (
    <EnLegalArticle title="Cancellation Rights">
      <h2>Your right to cancel</h2>
      <p>
        If you are a consumer, you generally have the right to cancel this contract within 14 days
        without giving any reason, under the Consumer Contracts (Information, Cancellation and
        Additional Charges) Regulations 2013. The cancellation period is 14 days from the day the
        contract is concluded.
      </p>
      <p>
        To exercise your right to cancel, you must inform us — the service provider identified in our{' '}
        <a href="/en/legal/business-info">Business Information</a> page, email:
        support@cybertestify.com — of your decision to cancel by a clear statement (for example, an
        email). To meet the cancellation deadline, it is sufficient for you to send your communication
        before the cancellation period has expired.
      </p>

      <h2>Effects of cancellation</h2>
      <p>
        If you cancel this contract, we will reimburse all payments received from you without undue
        delay, and no later than 14 days from the day on which we are informed of your decision to
        cancel, subject to the waiver explained below where you have asked us to begin the service
        immediately.
      </p>

      <h2>Loss of the right to cancel — digital services performed immediately</h2>
      <p>
        For a contract for the supply of a service (including digital services not supplied on a
        tangible medium), you will lose your right to cancel once the service has been fully performed,
        where performance has begun with your prior express consent and your acknowledgement that you
        will lose your right to cancel once the contract has been fully performed.
      </p>
      <p>Accordingly, before the scan begins, we ask you to:</p>
      <ol>
        <li>
          expressly consent to us beginning the service before the end of the 14-day cancellation
          period; and
        </li>
        <li>
          acknowledge that you will lose your right to cancel once the service has been fully
          performed.
        </li>
      </ol>
      <p>
        Because the security scan is a digital service performed immediately after you place your
        order, we obtain this express consent and acknowledgement separately during checkout. Without
        this consent, we will not begin performance before the cancellation period has expired.
      </p>

      <h2>Model cancellation form</h2>
      <p>
        (If you wish to cancel the contract, you can complete this form and email it to
        support@cybertestify.com.)
      </p>
      <p style={{ whiteSpace: 'pre-line' }}>
        {`— To: [Service provider, see Business Information], support@cybertestify.com
— I/We hereby give notice that I/We cancel my/our contract for the following service: [Order number / package]
— Ordered on / received on: [Date]
— Name of consumer(s): [Name]
— Address of consumer(s): [Address]
— Date: [Date]`}
      </p>
    </EnLegalArticle>
  );
}
