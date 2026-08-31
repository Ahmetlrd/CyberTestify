// ENTWURF — kullanıcının sağladığı metin BİREBİR yerleştirildi (yeniden yazılmadı/genişletilmedi).
// Vor der Veröffentlichung von einer Rechtsanwältin / einem Rechtsanwalt prüfen lassen.
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { DeLegalArticle } from '../../../../components/DeLegalArticle';

export const metadata: Metadata = {
  title: 'Allgemeine Geschäftsbedingungen — CyberTestify',
  description: 'AGB von CyberTestify für den automatisierten Sicherheits-Pre-Assessment-Service.',
  alternates: { canonical: '/de/legal/agb' },
  robots: { index: true, follow: true },
};

// (Deutschland) nur /de — andere Regionen haben diesen Slug nicht.
export default function Page({ params }: { params: { region: string } }) {
  if (params.region !== 'de') notFound();
  return (
    <DeLegalArticle title="Allgemeine Geschäftsbedingungen">

      <h2>1. Leistungsbeschreibung</h2>
      <p>
        CyberTestify bietet automatisierte Sicherheits-Pre-Assessments und Scans für Websites und
        Webanwendungen an. Der Service dient der Identifizierung potenzieller Sicherheitsprobleme mit
        automatisierten und weitgehend nicht-intrusiven Methoden.
      </p>
      <p>
        <strong>Wichtig:</strong> CyberTestify ist kein formeller Penetrationstest, kein
        Sicherheitsaudit und keine Zertifizierung (einschließlich ASV, QSA, ISO 27001 oder
        vergleichbarer Prüfungen). Berichte werden mit KI-Unterstützung erstellt und sollten nicht
        ohne unabhängige Überprüfung als alleinige Grundlage für Sicherheitsentscheidungen verwendet
        werden.
      </p>

      <h2>2. Vertragsschluss und Konto</h2>
      <p>
        Sie müssen mindestens 18 Jahre alt sein und geschäftsfähig sein. Sie sind für die
        Geheimhaltung Ihrer Zugangsdaten verantwortlich.
      </p>

      <h2>3. Domaininhaberschaft und Autorisierung</h2>
      <p>
        Sie dürfen nur Domains oder Systeme einreichen, die Sie besitzen oder für die Sie
        ausdrückliche Berechtigung zum Testen haben. Mit der Einreichung bestätigen Sie, dass Sie
        dazu berechtigt sind. Wir behalten uns vor, Scans abzulehnen oder abzubrechen, wenn die
        Berechtigung nicht nachgewiesen werden kann.
      </p>

      <h2>4. Leistungsumfang</h2>
      <p>
        Jedes Paket hat einen definierten Umfang (siehe Preisseite). Scans erfolgen nach bestem
        Bemühen. Die Ergebnisse hängen von der Konfiguration, Technologie und Erreichbarkeit des
        Ziels ab. Einige Prüfungen können als „außerhalb des Umfangs“ oder „nicht getestet“
        ausgewiesen werden, wenn die Struktur des Ziels dies nicht zulässt. Dies ist normal und
        stellt keinen Mangel dar.
      </p>
      <p>
        Wir folgen dem Ansatz „Nachweisen, nicht ausnutzen“. Wir führen keine destruktiven Tests,
        Datenänderungen oder echte Exploitation durch.
      </p>

      <h2>5. Berichte</h2>
      <p>
        Berichte werden verschlüsselt bereitgestellt und sind mit einem einzigartigen Code
        zugänglich. Die Berichte sind vertraulich und nur für den bestellenden Kunden bestimmt.
      </p>

      <h2>6. Preise und Zahlung</h2>
      <p>
        Es gelten die zum Zeitpunkt der Bestellung angezeigten Preise (inkl. gesetzlicher Steuern).
        Die Zahlung ist vor Beginn des Scans fällig. Nach Beginn des Scans sind die Gebühren
        grundsätzlich nicht erstattungsfähig, es sei denn, zwingendes Recht schreibt etwas anderes
        vor.
      </p>

      <h2>7. Zulässige Nutzung</h2>
      <p>
        Der Service darf nicht zum Scannen fremder Systeme ohne Berechtigung, zum Angriff auf Dritte
        oder für rechtswidrige Zwecke verwendet werden. Bei Missbrauch können wir den Zugang sperren
        oder beenden.
      </p>

      <h2>8. Haftung</h2>
      <p>Soweit gesetzlich zulässig:</p>
      <ul>
        <li>Der Service wird „wie besehen“ bereitgestellt.</li>
        <li>Wir garantieren nicht, dass jeder mögliche Sicherheitsfehler gefunden wird.</li>
        <li>Wir haften nicht für indirekte, zufällige oder Folgeschäden, entgangenen Gewinn oder Datenverlust.</li>
        <li>Unsere Gesamthaftung ist auf den Betrag beschränkt, den Sie für den konkreten Scan bezahlt haben, aus dem der Anspruch entsteht.</li>
      </ul>
      <p>
        Die Haftung für Vorsatz, grobe Fahrlässigkeit sowie für Schäden aus der Verletzung des
        Lebens, des Körpers oder der Gesundheit bleibt unberührt. Ebenso unberührt bleibt die Haftung
        nach dem Produkthaftungsgesetz.
      </p>

      <h2>9. Geistiges Eigentum</h2>
      <p>
        Alle Rechte an der CyberTestify-Plattform, der Methodik und den Berichtsvorlagen verbleiben
        bei uns. Sie erhalten ein beschränktes Recht zur Nutzung des Berichts für interne
        Sicherheitszwecke.
      </p>

      <h2>10. Anwendbares Recht</h2>
      <p>
        Es gilt das Recht der Bundesrepublik Deutschland unter Ausschluss des UN-Kaufrechts.
        Zwingende Verbraucherschutzvorschriften Ihres Wohnsitzlandes bleiben unberührt.
      </p>

      <h2>11. Änderungen</h2>
      <p>
        Wir können diese AGB von Zeit zu Zeit aktualisieren. Für eine Bestellung gilt die zum
        Zeitpunkt des Vertragsschlusses veröffentlichte Fassung.
      </p>

      <h2>12. Kontakt</h2>
      <p><a href="mailto:support@cybertestify.com">support@cybertestify.com</a></p>
    </DeLegalArticle>
  );
}
