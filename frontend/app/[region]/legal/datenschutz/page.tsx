// ENTWURF — kullanıcının sağladığı metin BİREBİR yerleştirildi (yeniden yazılmadı/genişletilmedi).
// Vor der Veröffentlichung von einer Rechtsanwältin / einem Rechtsanwalt prüfen lassen.
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { DeLegalArticle } from '../../../../components/DeLegalArticle';

export const metadata: Metadata = {
  title: 'Datenschutzerklärung — CyberTestify',
  description: 'Datenschutzerklärung von CyberTestify nach DSGVO.',
  alternates: { canonical: '/de/legal/datenschutz' },
  robots: { index: true, follow: true },
};

// (Deutschland) nur /de — andere Regionen haben diesen Slug nicht.
export default function Page({ params }: { params: { region: string } }) {
  if (params.region !== 'de') notFound();
  return (
    <DeLegalArticle title="Datenschutzerklärung">
      <p><em>Stand: 31. August 2026</em></p>

      <h2>1. Verantwortlicher</h2>
      <p>
        CyberTestify („wir“, „uns“) ist ein automatisierter Sicherheits-Pre-Assessment-Service. Bei
        der Verarbeitung personenbezogener Daten von Kunden in der Europäischen Union beachten wir
        die Datenschutz-Grundverordnung (DSGVO).
      </p>

      <h2>2. Welche Daten wir erheben</h2>
      <p>Wir können folgende Daten verarbeiten:</p>
      <ul>
        <li>E-Mail-Adresse und Name (bei Kontoerstellung oder Bestellung)</li>
        <li>Domainname / URL, die Sie zum Scannen einreichen</li>
        <li>Zahlungsinformationen (werden über unseren Zahlungsdienstleister abgewickelt; wir speichern keine vollständigen Kartendaten)</li>
        <li>Technische Daten (IP-Adresse, Browsertyp, Geräteinformationen) zur Sicherheit und Betrugsprävention</li>
        <li>Scan-bezogene Daten, die streng auf das von Ihnen autorisierte Ziel beschränkt sind</li>
      </ul>

      <h2>3. Zwecke der Verarbeitung</h2>
      <p>Wir verwenden die Daten, um:</p>
      <ul>
        <li>den Sicherheitsscan durchzuführen und den verschlüsselten Bericht bereitzustellen</li>
        <li>die Domaininhaberschaft zu verifizieren</li>
        <li>Zahlungen abzuwickeln und Betrug zu verhindern</li>
        <li>mit Ihnen über Ihre Bestellung zu kommunizieren</li>
        <li>unseren Service zu verbessern und zu sichern</li>
      </ul>
      <p>Wir verkaufen Ihre personenbezogenen Daten nicht.</p>

      <h2>4. Rechtsgrundlagen</h2>
      <ul>
        <li>Vertragserfüllung (Art. 6 Abs. 1 lit. b DSGVO)</li>
        <li>Berechtigte Interessen (Sicherheit, Betrugsprävention, Serviceverbesserung) (Art. 6 Abs. 1 lit. f DSGVO)</li>
        <li>Rechtliche Verpflichtungen, soweit anwendbar</li>
      </ul>

      <h2>5. Speicherdauer</h2>
      <ul>
        <li>Konten- und Bestelldaten: solange Ihr Konto aktiv ist und anschließend für einen angemessenen Zeitraum aus rechtlichen und buchhalterischen Gründen</li>
        <li>Scan-Daten und Berichte: nur so lange, wie zur Bereitstellung des Berichts und für begrenzten Support erforderlich; Berichte sind Ende-zu-Ende verschlüsselt</li>
        <li>Wir speichern Daten nicht länger als nötig (Datenminimierung)</li>
      </ul>

      <h2>6. Weitergabe von Daten</h2>
      <p>Wir können Daten an folgende Empfänger weitergeben:</p>
      <ul>
        <li>Zahlungsdienstleister</li>
        <li>Infrastruktur- und E-Mail-Dienstleister (auf Grundlage von Auftragsverarbeitungsverträgen)</li>
        <li>Behörden, wenn gesetzlich vorgeschrieben</li>
      </ul>
      <p>Wir geben Daten nicht zu Marketingzwecken an Dritte weiter.</p>

      <h2>7. Internationale Datenübermittlungen</h2>
      <p>
        Daten können außerhalb der EU/des EWR verarbeitet werden. In diesen Fällen verwenden wir
        geeignete Garantien (z. B. Standardvertragsklauseln), soweit erforderlich.
      </p>

      <h2>8. Ihre Rechte</h2>
      <p>Nach der DSGVO haben Sie das Recht auf:</p>
      <ul>
        <li>Auskunft</li>
        <li>Berichtigung</li>
        <li>Löschung</li>
        <li>Einschränkung der Verarbeitung</li>
        <li>Datenübertragbarkeit</li>
        <li>Widerspruch gegen die Verarbeitung</li>
        <li>Beschwerde bei einer Aufsichtsbehörde</li>
      </ul>
      <p>Zur Ausübung Ihrer Rechte kontaktieren Sie: <a href="mailto:support@cybertestify.com">support@cybertestify.com</a></p>

      <h2>9. Sicherheit</h2>
      <p>
        Wir setzen technische und organisatorische Maßnahmen ein, einschließlich der Verschlüsselung
        von Berichten, Zugriffskontrollen und der Isolation der Scan-Umgebungen.
      </p>

      <h2>10. Kontakt</h2>
      <p>Für datenschutzbezogene Anfragen: <a href="mailto:support@cybertestify.com">support@cybertestify.com</a></p>
    </DeLegalArticle>
  );
}
