import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { DeLegalArticle } from '../../../../components/DeLegalArticle';

export const metadata: Metadata = {
  title: 'Widerrufsbelehrung — CyberTestify',
  description: 'Widerrufsrecht für Verbraucher und Hinweise zum Erlöschen bei digitalen Dienstleistungen.',
  alternates: { canonical: '/de/legal/widerruf' },
  robots: { index: false, follow: true },
};

// (Almanya) Widerrufsbelehrung — /de'ye özgü. Checkout'taki iki-adımlı onay AKIŞI ayrı chunk'ta gelecek.
export default function WiderrufPage({ params }: { params: { region: string } }) {
  if (params.region !== 'de') notFound();
  return (
    <DeLegalArticle title="Widerrufsbelehrung">
      <h2>Widerrufsrecht</h2>
      <p>
        Sie haben das Recht, binnen vierzehn Tagen ohne Angabe von Gründen diesen Vertrag zu widerrufen.
        Die Widerrufsfrist beträgt vierzehn Tage ab dem Tag des Vertragsschlusses.
      </p>
      <p>
        Um Ihr Widerrufsrecht auszuüben, müssen Sie uns (dem im{' '}
        <a href="/de/legal/impressum">Impressum</a> genannten Diensteanbieter, E-Mail:
        support@cybertestify.com) mittels einer eindeutigen Erklärung (z. B. per E-Mail) über Ihren
        Entschluss, diesen Vertrag zu widerrufen, informieren. Zur Wahrung der Widerrufsfrist reicht es
        aus, dass Sie die Mitteilung über die Ausübung des Widerrufsrechts vor Ablauf der Widerrufsfrist
        absenden.
      </p>

      <h2>Folgen des Widerrufs</h2>
      <p>
        Wenn Sie diesen Vertrag widerrufen, haben wir Ihnen alle Zahlungen, die wir von Ihnen erhalten
        haben, unverzüglich und spätestens binnen vierzehn Tagen ab dem Tag zurückzuzahlen, an dem die
        Mitteilung über Ihren Widerruf dieses Vertrags bei uns eingegangen ist.
      </p>

      <h2>Vorzeitiges Erlöschen des Widerrufsrechts</h2>
      <p>
        Bei einem Vertrag über die Bereitstellung digitaler Inhalte oder Dienstleistungen, die nicht
        auf einem körperlichen Datenträger geliefert werden, erlischt Ihr Widerrufsrecht, wenn wir mit
        der Ausführung des Vertrags begonnen haben, nachdem Sie
      </p>
      <ol>
        <li>
          ausdrücklich zugestimmt haben, dass wir mit der Ausführung des Vertrags vor Ablauf der
          Widerrufsfrist beginnen, und
        </li>
        <li>
          Ihre Kenntnis davon bestätigt haben, dass Sie durch Ihre Zustimmung mit Beginn der Ausführung
          des Vertrags Ihr Widerrufsrecht verlieren (§ 356 Abs. 5 BGB).
        </li>
      </ol>
      <p>
        Da der Sicherheitsscan als digitale Dienstleistung unmittelbar nach der Bestellung ausgeführt
        wird, holen wir diese ausdrückliche Zustimmung und Bestätigung im Bestellvorgang gesondert ein.
        Ohne diese Zustimmung beginnen wir nicht vor Ablauf der Widerrufsfrist mit der Ausführung.
      </p>

      <h2>Muster-Widerrufsformular</h2>
      <p>
        (Wenn Sie den Vertrag widerrufen wollen, können Sie dieses Formular ausfüllen und an
        support@cybertestify.com senden.)
      </p>
      <p style={{ whiteSpace: 'pre-line' }}>
        {`— An: [Diensteanbieter, siehe Impressum], support@cybertestify.com
— Hiermit widerrufe(n) ich/wir den von mir/uns abgeschlossenen Vertrag über die folgende Dienstleistung: [Bestellnummer / Paket]
— Bestellt am / erhalten am: [Datum]
— Name des/der Verbraucher(s): [Name]
— Anschrift des/der Verbraucher(s): [Anschrift]
— Datum: [Datum]`}
      </p>
    </DeLegalArticle>
  );
}
