// DRAFT — must be reviewed by a qualified UK solicitor before publication. Business details are placeholders.
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { EnLegalArticle } from '../../../../components/EnLegalArticle';

export const metadata: Metadata = {
  title: 'Business Information — CyberTestify',
  description: 'Provider and business information under the Companies Act 2006 and the E-Commerce (EC Directive) Regulations 2002.',
  alternates: { canonical: '/en/legal/business-info' },
  robots: { index: false, follow: true },
};

// (United Kingdom) Business Information — /en only. Other regions do not have this slug (notFound).
export default function BusinessInfoPage({ params }: { params: { region: string } }) {
  if (params.region !== 'en') notFound();
  return (
    <EnLegalArticle title="Business Information">
      <p>
        The following information is provided in accordance with the Companies Act 2006 and the
        Electronic Commerce (EC Directive) Regulations 2002, which require service providers to make
        certain business details easily, directly and permanently accessible.
      </p>

      <h2>Service provider</h2>
      <p>
        {/* PLACEHOLDER — real business details are entered by the operator (not invented). */}
        [Company name — to be provided]<br />
        [Trading name, if different]<br />
        [Legal form, e.g. private limited company]
      </p>

      <h2>Geographic address</h2>
      <p>
        [Registered office address]<br />
        [Street and number]<br />
        [Town/city, postcode]<br />
        [Country]
      </p>

      <h2>Contact</h2>
      <p>
        Email: support@cybertestify.com<br />
        Telephone: [Telephone number, if applicable]
      </p>

      <h2>Company registration</h2>
      <p>
        Registered in [England and Wales / Scotland / Northern Ireland]<br />
        Company registration number: [Company number]<br />
        Registered office: [Registered office address, if different from above]
      </p>

      <h2>VAT</h2>
      <p>
        VAT registration number: [VAT number, if applicable]
      </p>

      <h2>Regulatory information</h2>
      <p>
        [Details of any relevant trade register, supervisory authority or professional body, if
        applicable — to be provided.]
      </p>

      <h2>Complaints and dispute resolution</h2>
      <p>
        If you have a complaint, please contact us at support@cybertestify.com in the first instance.
        [Details of any applicable alternative dispute resolution (ADR) scheme, if used, to be
        provided.]
      </p>
    </EnLegalArticle>
  );
}
