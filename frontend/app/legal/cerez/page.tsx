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
      </ul>

      <h3>Kullanmadığımız Çerezler</h3>
      <p>
        Şu an <strong>izleyici/analitik veya reklam çerezi kullanılmamaktadır.</strong> İleride böyle
        çerezler eklenirse, bunlar <strong>rızanız alınmadan önce yüklenmeyecek</strong> ve bu sayfa
        ile çerez rıza yönetimi güncellenecektir.
      </p>

      <h3>Çerezleri Yönetme</h3>
      <p>Tarayıcı ayarlarınızdan çerezleri/yerel depolamayı silebilir veya engelleyebilirsiniz; ancak zorunlu çerezler engellenirse oturum açma gibi işlevler çalışmayabilir.</p>
    </LegalArticle>
  );
}
