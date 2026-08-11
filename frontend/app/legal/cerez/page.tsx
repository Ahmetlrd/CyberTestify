import { LegalArticle } from '../../../components/LegalArticle';

export const metadata = { title: 'Çerez Politikası — CyberTestify' };

export default function Page() {
  return (
    <LegalArticle title="Çerez Politikası">
      <p>
        Bu politika, sitemizde kullanılan çerezleri (ve benzeri yerel depolama teknolojilerini)
        açıklar.
      </p>

      <h3>Kullandığımız Çerezler</h3>
      <ul>
        <li>
          <strong>Zorunlu/teknik:</strong> Oturumunuzu sürdürmek için tarayıcı yerel depolamasında
          (localStorage) tutulan oturum tokeni ve çerez tercihiniz. Bunlar hizmetin çalışması için
          gereklidir ve rıza gerektirmez.
        </li>
        <li>
          <strong>Analitik/ölçüm (rızaya bağlı):</strong> Deneyimi ölçüp iyileştirmek ve reklam
          performansını değerlendirmek için <strong>Google Analytics 4</strong> ve <strong>Microsoft
          Clarity</strong> kullanılır. Bu çerezler <strong>yalnızca açık rızanız (banner’dan “Kabul Et”)
          sonrasında</strong> çalışır; rıza vermezseniz veya “Reddet” derseniz yüklenmez. Google Consent
          Mode ile onay öncesi izleme çerezi yazılmaz.
        </li>
      </ul>
      <p style={{ fontSize: 13 }}>
        Bu araçlar için veriler yurt dışındaki sağlayıcılara (Google LLC, Microsoft Corporation — ABD)
        aktarılabilir. Rızanızı istediğiniz zaman sayfa altındaki <strong>“Çerez tercihleri”</strong>
        bağlantısından değiştirebilirsiniz.
      </p>

      <h3>Çerezleri Yönetme</h3>
      <p>Analitik/ölçüm çerezleri için onayınızı, sayfa altındaki <strong>“Çerez tercihleri”</strong> bağlantısıyla dilediğiniz an geri alabilir veya değiştirebilirsiniz. Ayrıca tarayıcı ayarlarınızdan çerezleri/yerel depolamayı silebilir veya engelleyebilirsiniz; ancak zorunlu çerezler engellenirse oturum açma gibi işlevler çalışmayabilir.</p>
    </LegalArticle>
  );
}
