import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { DeLegalArticle } from '../../../../components/DeLegalArticle';

export const metadata: Metadata = {
  title: 'Datenschutzerklärung — CyberTestify',
  description: 'Informationen zur Verarbeitung personenbezogener Daten nach der DSGVO.',
  alternates: { canonical: '/de/legal/datenschutz' },
  robots: { index: false, follow: true },
};

// (Almanya) Datenschutzerklärung — GDPR'a göre yeniden yazıldı (KVKK çevirisi DEĞİL). /de'ye özgü.
export default function DatenschutzPage({ params }: { params: { region: string } }) {
  if (params.region !== 'de') notFound();
  return (
    <DeLegalArticle title="Datenschutzerklärung">
      <p>
        Diese Datenschutzerklärung informiert Sie über die Verarbeitung personenbezogener Daten bei
        der Nutzung von CyberTestify gemäß der Datenschutz-Grundverordnung (DSGVO).
      </p>

      <h2>1. Verantwortlicher</h2>
      <p>
        Verantwortlicher im Sinne des Art. 4 Nr. 7 DSGVO ist der im{' '}
        <a href="/de/legal/impressum">Impressum</a> genannte Diensteanbieter.
        {' '}[Kontaktdaten des/der Datenschutzbeauftragten, sofern bestellt.]
      </p>

      <h2>2. Verarbeitete Daten und Zwecke</h2>
      <ul>
        <li><strong>Konto- und Bestelldaten</strong> (Name, E-Mail-Adresse, verifizierte Domain, Bestell- und Zahlungsstatus) — zur Bereitstellung des Dienstes und zur Vertragserfüllung.</li>
        <li><strong>Scan-Ergebnisse</strong> (technische Befunde zu der von Ihnen verifizierten Domain) — zur Erstellung Ihres Sicherheitsberichts.</li>
        <li><strong>Server- und Protokolldaten</strong> (IP-Adresse, Zeitstempel, technische Zugriffsdaten) — zum sicheren Betrieb und zur Missbrauchsabwehr.</li>
        <li><strong>Einwilligungsnachweise</strong> (Zeitpunkt, IP, Textversion) — zum Nachweis erteilter Einwilligungen.</li>
      </ul>

      <h2>3. Rechtsgrundlagen</h2>
      <ul>
        <li>Art. 6 Abs. 1 lit. b DSGVO — Erfüllung des Vertrags (Bereitstellung des Scans und des Berichts).</li>
        <li>Art. 6 Abs. 1 lit. c DSGVO — Erfüllung rechtlicher Pflichten (z. B. handels- und steuerrechtliche Aufbewahrung).</li>
        <li>Art. 6 Abs. 1 lit. f DSGVO — berechtigte Interessen (sicherer Betrieb, Missbrauchsabwehr).</li>
        <li>Art. 6 Abs. 1 lit. a DSGVO — Einwilligung, soweit gesondert eingeholt.</li>
      </ul>

      <h2>4. Scope-Sperre und Maskierung personenbezogener Daten</h2>
      <p>
        Ein Scan kann technisch ausschließlich die von Ihnen per DNS verifizierte Domain erreichen
        (Scope-Sperre). Während eines Scans angetroffene personenbezogene Daten werden strukturell
        maskiert, bevor sie an KI-Komponenten übermittelt werden, um die Weitergabe von Klardaten zu
        vermeiden (Datenminimierung, Art. 5 Abs. 1 lit. c DSGVO).
      </p>

      <h2>5. Empfänger und Auftragsverarbeiter</h2>
      <p>
        Zur Erbringung des Dienstes setzen wir sorgfältig ausgewählte Dienstleister ein (Hosting,
        Zahlungsabwicklung, E-Mail-Versand, KI-Verarbeitung). Diese verarbeiten Daten als
        Auftragsverarbeiter nach Art. 28 DSGVO auf Grundlage entsprechender Verträge.
      </p>

      <h2>6. Übermittlung in Drittländer</h2>
      <p>
        Für bestimmte KI-Verarbeitungsschritte kann eine Übermittlung an Anbieter mit Sitz in den USA
        erforderlich sein. Eine solche Übermittlung erfolgt nur auf Grundlage geeigneter Garantien
        gemäß Art. 44 ff. DSGVO (z. B. Standardvertragsklauseln der EU-Kommission) und — soweit
        erforderlich — Ihrer ausdrücklichen Einwilligung. Zur Datenminimierung werden personenbezogene
        Daten zuvor maskiert (siehe Ziffer 4).
      </p>

      <h2>7. Speicherdauer</h2>
      <p>
        Personenbezogene Daten werden nur so lange gespeichert, wie es für die genannten Zwecke oder
        zur Erfüllung gesetzlicher Aufbewahrungsfristen erforderlich ist. [Konkrete Fristen werden vom
        Betreiber ergänzt.] Berichte werden verschlüsselt bereitgestellt und nach der festgelegten
        Frist gelöscht.
      </p>

      <h2>8. Ihre Rechte</h2>
      <p>Sie haben nach der DSGVO das Recht auf:</p>
      <ul>
        <li>Auskunft (Art. 15 DSGVO),</li>
        <li>Berichtigung (Art. 16 DSGVO),</li>
        <li>Löschung (Art. 17 DSGVO),</li>
        <li>Einschränkung der Verarbeitung (Art. 18 DSGVO),</li>
        <li>Datenübertragbarkeit (Art. 20 DSGVO),</li>
        <li>Widerspruch gegen die Verarbeitung (Art. 21 DSGVO).</li>
      </ul>
      <p>
        Eine erteilte Einwilligung können Sie jederzeit mit Wirkung für die Zukunft widerrufen. Zur
        Ausübung Ihrer Rechte genügt eine Nachricht an support@cybertestify.com.
      </p>

      <h2>9. Beschwerderecht bei einer Aufsichtsbehörde</h2>
      <p>
        Sie haben das Recht, sich bei einer Datenschutz-Aufsichtsbehörde zu beschweren (Art. 77 DSGVO),
        insbesondere in dem Mitgliedstaat Ihres Aufenthaltsorts oder des Orts des mutmaßlichen Verstoßes.
      </p>

      <h2>10. Cookies</h2>
      <p>
        Es werden nur technisch notwendige Cookies eingesetzt, die für den Betrieb des Dienstes
        erforderlich sind (z. B. Sitzungs- und Regionsauswahl). [Weitere Angaben zu etwaigen
        Analyse-/Marketing-Cookies werden ergänzt, sobald diese eingesetzt werden — mit vorheriger
        Einwilligung.]
      </p>
    </DeLegalArticle>
  );
}
