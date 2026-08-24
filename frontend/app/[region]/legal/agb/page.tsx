import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { DeLegalArticle } from '../../../../components/DeLegalArticle';

export const metadata: Metadata = {
  title: 'AGB — CyberTestify',
  description: 'Allgemeine Geschäftsbedingungen für die Nutzung von CyberTestify.',
  alternates: { canonical: '/de/legal/agb' },
  robots: { index: false, follow: true },
};

// (Almanya) AGB (Allgemeine Geschäftsbedingungen) — Alman tüketici hukukuna göre taslak. /de'ye özgü.
export default function AgbPage({ params }: { params: { region: string } }) {
  if (params.region !== 'de') notFound();
  return (
    <DeLegalArticle title="Allgemeine Geschäftsbedingungen (AGB)">
      <h2>1. Geltungsbereich und Anbieter</h2>
      <p>
        Diese Allgemeinen Geschäftsbedingungen gelten für alle über CyberTestify abgeschlossenen
        Verträge über die Nutzung der Sicherheits-Vorabbewertung. Anbieter ist der im{' '}
        <a href="/de/legal/impressum">Impressum</a> genannte Diensteanbieter.
      </p>

      <h2>2. Leistungsbeschreibung</h2>
      <p>
        CyberTestify erbringt eine KI-gestützte, automatisierte Sicherheits-<em>Vorabbewertung</em> für
        eine von Ihnen per DNS verifizierte Domain. Das Ergebnis ist ein technischer Bericht. Der
        Dienst ist <strong>kein</strong> formeller Penetrationstest, kein Audit und keine
        Zertifizierung und ersetzt diese nicht. Für die autonomen bzw. deterministischen Verfahren
        wird keine bestimmte Trefferzahl oder Vollständigkeit garantiert.
      </p>

      <h2>3. Vertragsschluss</h2>
      <p>
        Die Darstellung der Pakete stellt kein rechtlich bindendes Angebot dar. Mit dem Absenden der
        Bestellung geben Sie ein verbindliches Angebot ab; der Vertrag kommt mit unserer Bestätigung
        bzw. mit Bereitstellung des Dienstes zustande.
      </p>

      <h2>4. Voraussetzung: Berechtigung am Ziel</h2>
      <p>
        Sie dürfen einen Scan nur für Domains/Systeme beauftragen, deren Inhaber Sie sind oder für die
        Sie eine ausdrückliche schriftliche Berechtigung besitzen. Die Verifizierung der Domain-
        Inhaberschaft ist Voraussetzung für die Durchführung.
      </p>

      <h2>5. Preise und Zahlung</h2>
      <p>
        Es gelten die zum Zeitpunkt der Bestellung angegebenen Preise in Euro (EUR), inklusive der
        gesetzlichen Umsatzsteuer, soweit anwendbar. Die Zahlung erfolgt über den bereitgestellten
        Zahlungsdienstleister. Eine Rechnung/Quittung wird elektronisch bereitgestellt.
      </p>

      <h2>6. Bereitstellung des Berichts</h2>
      <p>
        Der Bericht wird nach Abschluss des Scans elektronisch, Ende-zu-Ende-verschlüsselt und mit
        einem Einmal-Zugangscode bereitgestellt. Es erfolgt keine Lieferung auf einem körperlichen
        Datenträger.
      </p>

      <h2>7. Widerrufsrecht und Erlöschen des Widerrufsrechts</h2>
      <p>
        Verbrauchern steht grundsätzlich ein Widerrufsrecht zu (siehe{' '}
        <a href="/de/legal/widerruf">Widerrufsbelehrung</a>). Bei Verträgen über die Bereitstellung
        digitaler Inhalte/Dienstleistungen, die nicht auf einem körperlichen Datenträger geliefert
        werden, <strong>erlischt das Widerrufsrecht</strong>, wenn wir mit der Ausführung begonnen
        haben, nachdem Sie ausdrücklich zugestimmt haben, dass wir vor Ablauf der Widerrufsfrist mit
        der Ausführung beginnen, und Sie Ihre Kenntnis davon bestätigt haben, dass Sie durch diese
        Zustimmung Ihr Widerrufsrecht verlieren (§ 356 Abs. 5 BGB). Diese Zustimmung wird im
        Bestellvorgang gesondert eingeholt.
      </p>

      <h2>8. Haftung</h2>
      <p>
        Wir haften unbeschränkt bei Vorsatz und grober Fahrlässigkeit sowie nach dem
        Produkthaftungsgesetz und bei Verletzung von Leben, Körper oder Gesundheit. Bei einfacher
        Fahrlässigkeit haften wir nur bei Verletzung wesentlicher Vertragspflichten (Kardinalpflichten)
        und begrenzt auf den vertragstypischen, vorhersehbaren Schaden. Im Übrigen ist die Haftung
        ausgeschlossen. Der Dienst liefert eine Vorabbewertung; die Beseitigung etwaiger Schwachstellen
        und die Absicherung Ihrer Systeme liegt in Ihrer Verantwortung.
      </p>

      <h2>9. Anwendbares Recht</h2>
      <p>
        Es gilt das Recht der Bundesrepublik Deutschland unter Ausschluss des UN-Kaufrechts. Zwingende
        Verbraucherschutzvorschriften des Staates Ihres gewöhnlichen Aufenthalts bleiben unberührt.
      </p>
    </DeLegalArticle>
  );
}
