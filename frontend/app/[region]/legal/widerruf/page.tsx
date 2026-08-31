// ENTWURF — kullanıcının sağladığı metin BİREBİR yerleştirildi (yeniden yazılmadı/genişletilmedi).
// Vor der Veröffentlichung von einer Rechtsanwältin / einem Rechtsanwalt prüfen lassen.
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { DeLegalArticle } from '../../../../components/DeLegalArticle';

export const metadata: Metadata = {
  title: 'Widerrufsbelehrung — CyberTestify',
  description: 'Widerrufsbelehrung und Erstattungsregelungen von CyberTestify.',
  alternates: { canonical: '/de/legal/widerruf' },
  robots: { index: true, follow: true },
};

// (Deutschland) nur /de — andere Regionen haben diesen Slug nicht.
export default function Page({ params }: { params: { region: string } }) {
  if (params.region !== 'de') notFound();
  return (
    <DeLegalArticle title="Widerrufsbelehrung">

      <h2>1. Digitale Inhalte / Dienstleistung</h2>
      <p>
        CyberTestify erbringt eine digitale Dienstleistung (automatisierter Sicherheitsscan und
        Berichtserstellung). Sobald Sie eine Bestellung aufgegeben haben und der Scan-Prozess
        begonnen hat, hat die Ausführung der Dienstleistung begonnen.
      </p>

      <h2>2. Widerrufsrecht</h2>
      <p>Verbrauchern steht grundsätzlich ein 14-tägiges Widerrufsrecht zu.</p>
      <p>
        Bei Verträgen über digitale Inhalte, die nicht auf einem körperlichen Datenträger geliefert
        werden, erlischt das Widerrufsrecht, wenn:
      </p>
      <ul>
        <li>Sie ausdrücklich zugestimmt haben, dass wir mit der Ausführung vor Ablauf der Widerrufsfrist beginnen, und</li>
        <li>Sie Ihre Kenntnis davon bestätigt haben, dass Sie durch Ihre Zustimmung mit Beginn der Ausführung Ihr Widerrufsrecht verlieren.</li>
      </ul>
      <p>Mit der Bestellung und Bestätigung des Scans erklären Sie:</p>
      <ul>
        <li>dass Sie den sofortigen Beginn des Scans wünschen, und</li>
        <li>dass Sie Ihr Widerrufsrecht mit Beginn des Scans verlieren.</li>
      </ul>

      <h2>3. Erstattung</h2>
      <ul>
        <li>Vor Beginn des Scans: Sie können eine vollständige Erstattung verlangen, indem Sie <a href="mailto:support@cybertestify.com">support@cybertestify.com</a> kontaktieren.</li>
        <li>Nach Beginn des Scans: Eine Erstattung ist grundsätzlich ausgeschlossen, es sei denn, zwingendes Recht schreibt etwas anderes vor oder es liegt ein klarer Leistungsfehler unsererseits vor.</li>
      </ul>

      <h2>4. Leistungsstörung</h2>
      <p>
        Können wir einen Bericht aufgrund eines technischen Fehlers auf unserer Seite nicht liefern,
        haben Sie Anspruch auf vollständige Erstattung oder einen kostenlosen erneuten Scan nach
        unserer Wahl.
      </p>

      <h2>5. Kontakt</h2>
      <p>
        Für Widerrufs- oder Erstattungsanfragen:{' '}
        <a href="mailto:support@cybertestify.com">support@cybertestify.com</a><br />
        Bitte geben Sie Ihre Bestellnummer an.
      </p>

      <h2>6. Anwendbares Recht</h2>
      <p>Es gilt das Recht der Bundesrepublik Deutschland.</p>
    </DeLegalArticle>
  );
}
