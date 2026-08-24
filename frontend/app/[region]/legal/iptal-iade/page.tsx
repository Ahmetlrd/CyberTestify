import { LegalArticle } from '../../../../components/LegalArticle';
import { COMPANY } from '../../../../lib/company';

export const metadata = { title: 'Teslimat, İptal / İade & Cayma Koşulları — CyberTestify', alternates: { canonical: '/legal/iptal-iade' } };

export default function Page() {
  return (
    <LegalArticle title="Teslimat, İptal / İade ve Cayma Koşulları">
      <h3>Teslimat (Dijital Hizmet)</h3>
      <p>
        Sunulan hizmet, fiziksel bir ürün değil <strong>dijital/SaaS bir güvenlik ön-değerlendirme
        hizmetidir</strong>. Bu nedenle <strong>kargo veya fiziksel teslimat söz konusu değildir</strong>.
        Hizmet, ödeme onayının ardından <strong>elektronik ortamda anında</strong> sunulur: tarama başlar,
        rapor hazır olduğunda hesabınızın panelinde erişime açılır ve tek kullanımlık erişim kodu e-posta
        ile iletilir. Bu anlamda &quot;teslimat&quot;, raporun elektronik olarak erişime açılmasıdır.
      </p>

      <h3>Cayma Hakkı ve İstisnası</h3>
      <p>
        Mesafeli sözleşmelerde tüketicinin kural olarak 14 gün içinde cayma hakkı vardır. Ancak
        satın aldığınız güvenlik ön-değerlendirme hizmeti, <strong>elektronik ortamda anında ifa
        edilen bir hizmet/gayrimaddi mal</strong> niteliğindedir. Mesafeli Sözleşmeler
        Yönetmeliği&apos;nin ilgili maddesi (md. 15) uyarınca, <strong>açık onayınızla hizmetin
        ifasına başlanmasıyla birlikte cayma hakkınız sona erer.</strong>
      </p>
      <p>
        Bu nedenle sipariş sırasında, hizmetin cayma süresi dolmadan onayınızla başlatılacağını ve bu
        durumda cayma hakkınızı kaybedeceğinizi ayrıca (ayrı bir kutucukla) onaylamanız istenir. Bu
        onayı vermeden hizmet başlatılmaz.
      </p>

      <h3>İfaya Başlanmadan İptal</h3>
      <p>
        Ödemeyi yaptıktan sonra ancak tarama <strong>henüz başlamadan</strong> önce iptal talep
        ederseniz, ücret iadesi yapılır. Tarama başladıktan sonra hizmet ifa edilmeye başlandığından
        iade yapılamaz.
      </p>

      <h3>Ayıplı / Eksik İfa</h3>
      <p>
        Teknik bir hata nedeniyle taramanın hiç yapılamaması veya raporun üretilememesi halinde, bedel
        iadesi veya taramanın yeniden çalıştırılması sağlanır. Raporun içeriğine ilişkin
        değerlendirmeler, hizmetin niteliği gereği (yapay zeka üretimi, pasif kapsam) ayıp
        sayılmaz — bkz. <a href="/legal/sorumluluk-reddi">Sorumluluk Reddi</a>.
      </p>

      <h3>İletişim</h3>
      <p>İptal/iade talepleriniz için: {COMPANY.email}</p>
    </LegalArticle>
  );
}
