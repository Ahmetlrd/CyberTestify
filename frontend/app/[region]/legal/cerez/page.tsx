import { LegalArticle } from '../../../../components/LegalArticle';

export const metadata = { title: 'Çerez Politikası — CyberTestify', alternates: { canonical: '/legal/cerez' } };

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
          <strong>Analitik/ölçüm:</strong> Sitenin nasıl kullanıldığını anlamak ve deneyimi iyileştirmek
          için ölçüm ve analitik amaçlı çerezler kullanılır. Bu çerezler; sayfa görüntülemeleri, tıklamalar
          ve genel kullanım gibi verileri toplar. Kişisel bilgi girdiğiniz alanlar bu amaçla toplanmaz.
        </li>
      </ul>
      <p style={{ fontSize: 13 }}>
        Bu amaçla toplanan bazı veriler, hizmet aldığımız üçüncü taraf sağlayıcılar aracılığıyla yurt dışında
        işlenebilir. Çerezleri tarayıcı ayarlarınızdan silebilir veya engelleyebilirsiniz.
      </p>

      <h3>Çerezleri Yönetme</h3>
      <p>Tarayıcı ayarlarınızdan çerezleri/yerel depolamayı silebilir veya engelleyebilirsiniz. Ancak zorunlu teknik çerezler engellenirse oturum açma gibi işlevler çalışmayabilir.</p>
    </LegalArticle>
  );
}
