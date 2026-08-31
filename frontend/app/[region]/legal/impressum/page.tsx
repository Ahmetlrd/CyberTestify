// ENTWURF — kullanıcının sağladığı metin BİREBİR yerleştirildi (yeniden yazılmadı/genişletilmedi).
// Vor der Veröffentlichung von einer Rechtsanwältin / einem Rechtsanwalt prüfen lassen.
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { DeLegalArticle } from '../../../../components/DeLegalArticle';

export const metadata: Metadata = {
  title: 'Impressum — CyberTestify',
  description: 'Angaben gemäß § 5 TMG für CyberTestify.',
  alternates: { canonical: '/de/legal/impressum' },
  robots: { index: true, follow: true },
};

// (Deutschland) nur /de — andere Regionen haben diesen Slug nicht.
export default function Page({ params }: { params: { region: string } }) {
  if (params.region !== 'de') notFound();
  return (
    <DeLegalArticle title="Impressum">
      <p><strong>Angaben gemäß § 5 TMG:</strong></p>

      {/* PLATZHALTER — GERÇEK şirket unvanı, Registergericht/Registernummer, USt-IdNr. ve adres
          OPERATÖR tarafından doldurulmalıdır. Uydurulmadı; kullanıcının verdiği metin aynen korundu. */}
      <p>
        <strong>CyberTestify co</strong><br />
        Registriert in der Türkei
      </p>

      <h2>Kontakt</h2>
      <p>E-Mail: <a href="mailto:support@cybertestify.com">support@cybertestify.com</a></p>

      <p>
        CyberTestify ist ein automatisierter Sicherheits-Pre-Assessment-Service. Das Angebot richtet
        sich auch an Kunden in Deutschland und der Europäischen Union.
      </p>
      <p>
        Bei Fragen zum Service, zur Abrechnung oder zum Datenschutz wenden Sie sich bitte an die oben
        genannte E-Mail-Adresse.
      </p>
    </DeLegalArticle>
  );
}
