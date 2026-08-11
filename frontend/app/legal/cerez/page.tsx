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
          <strong>Analitik/ölçüm:</strong> Deneyimi ölçüp iyileştirmek ve reklam performansını
          değerlendirmek için <strong>Google Analytics 4</strong> ve <strong>Microsoft Clarity</strong>
          (oturum kaydı/ısı haritası) kullanılır. Bu araçlar sayfa görüntülemeleri, tıklamalar ve genel
          kullanım verilerini toplar. Kişisel bilgi girdiğiniz alanlar (ör. kimlik bilgileri) bu araçlara
          gönderilmez; hedef verileri güvenlik/gizlilik nedeniyle maskelenir.
        </li>
      </ul>
      <p style={{ fontSize: 13 }}>
        Bu araçlar için veriler yurt dışındaki sağlayıcılara (Google LLC, Microsoft Corporation — ABD)
        aktarılabilir. Çerezleri tarayıcı ayarlarınızdan silebilir veya engelleyebilirsiniz.
      </p>

      <h3>Çerezleri Yönetme</h3>
      <p>Tarayıcı ayarlarınızdan çerezleri/yerel depolamayı silebilir veya engelleyebilirsiniz; ayrıca analitik araçları tarayıcı eklentileriyle (ör. reklam/izleme engelleyiciler) kısıtlayabilirsiniz. Ancak zorunlu teknik çerezler engellenirse oturum açma gibi işlevler çalışmayabilir.</p>
    </LegalArticle>
  );
}
