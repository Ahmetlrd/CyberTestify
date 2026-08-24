import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { DeLegalArticle } from '../../../../components/DeLegalArticle';

export const metadata: Metadata = {
  title: 'Impressum — CyberTestify',
  description: 'Impressum und Anbieterkennzeichnung gemäß § 5 DDG.',
  alternates: { canonical: '/de/legal/impressum' },
  robots: { index: false, follow: true },
};

// (Almanya) Impressum — /de'ye özgü. /tr ve diğer bölgelerde bu slug YOK (notFound).
export default function ImpressumPage({ params }: { params: { region: string } }) {
  if (params.region !== 'de') notFound();
  return (
    <DeLegalArticle title="Impressum">
      <p>Angaben gemäß § 5 DDG (Digitale-Dienste-Gesetz).</p>

      <h2>Diensteanbieter</h2>
      <p>
        {/* PLATZHALTER — echte Unternehmensangaben werden vom Betreiber eingetragen (nicht erfunden). */}
        [Unternehmensname / Rechtsform]<br />
        [Straße und Hausnummer]<br />
        [PLZ, Ort]<br />
        [Land]
      </p>

      <h2>Vertreten durch</h2>
      <p>[Name der vertretungsberechtigten Person]</p>

      <h2>Kontakt</h2>
      <p>
        E-Mail: support@cybertestify.com<br />
        Telefon: [Telefonnummer]
      </p>

      <h2>Registereintrag</h2>
      <p>
        Eintragung im [Handelsregister / entsprechendes Register]<br />
        Registergericht: [Registergericht]<br />
        Registernummer: [Registernummer]
      </p>

      <h2>Umsatzsteuer-Identifikationsnummer</h2>
      <p>
        Umsatzsteuer-Identifikationsnummer gemäß § 27 a Umsatzsteuergesetz:<br />
        [USt-IdNr., sofern vorhanden]
      </p>

      <h2>Verantwortlich für den Inhalt nach § 18 Abs. 2 MStV</h2>
      <p>
        [Name]<br />
        [Anschrift, sofern abweichend]
      </p>

      <h2>Streitschlichtung</h2>
      <p>
        Die Europäische Kommission stellt eine Plattform zur Online-Streitbeilegung (OS) bereit:{' '}
        <a href="https://ec.europa.eu/consumers/odr/" target="_blank" rel="noopener noreferrer">https://ec.europa.eu/consumers/odr/</a>.
        Wir sind nicht verpflichtet und grundsätzlich nicht bereit, an Streitbeilegungsverfahren vor
        einer Verbraucherschlichtungsstelle teilzunehmen.
      </p>
    </DeLegalArticle>
  );
}
