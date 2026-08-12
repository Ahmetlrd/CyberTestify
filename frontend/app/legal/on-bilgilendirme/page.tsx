import { LegalArticle } from '../../../components/LegalArticle';
import { COMPANY } from '../../../lib/company';

export const metadata = { title: 'Ön Bilgilendirme Formu — CyberTestify' };

export default function Page() {
  return (
    <LegalArticle title="Ön Bilgilendirme Formu">
      <p>
        Bu form, Mesafeli Sözleşmeler Yönetmeliği md. 5 uyarınca, siparişinizi tamamlamadan önce
        sizi bilgilendirmek amacıyla hazırlanmıştır.
      </p>

      <h3>1. Satıcı / Hizmet Sağlayıcı</h3>
      <p>
        {COMPANY.brand}<br />
        E-posta: {COMPANY.email}
      </p>

      <h3>2. Hizmetin Temel Nitelikleri</h3>
      <p>
        Müşterinin sahipliğini/yetkisini doğruladığı kendi alan adına yönelik, pasif (saldırgan
        olmayan) otomatik güvenlik ön-değerlendirmesi ve şifreli rapor teslimi. Rapor, seçilen pakete
        göre kapsamı değişen dijital bir içeriktir. Resmi denetim/sertifikasyon değildir.
      </p>

      <h3>3. Fiyat</h3>
      <p>
        Her paketin fiyatı, sipariş ekranında <strong>tüm vergiler dahil</strong> Türk Lirası (TRY)
        olarak gösterilir. Sipariş özetinde ödeyeceğiniz toplam tutar açıkça belirtilir.
      </p>

      <h3>4. Ödeme ve İfa</h3>
      <p>
        Ödeme, PCI-DSS uyumlu ödeme kuruluşu <strong>iyzico</strong> üzerinden alınır. Ödeme
        onaylandıktan sonra tarama <strong>otomatik ve anında</strong> başlatılır; rapor hazır
        olduğunda panelinizde erişilebilir olur ve erişim kodu e-posta ile iletilir.
      </p>

      <h3>5. Cayma Hakkı</h3>
      <p>
        Hizmet dijital olarak ve <strong>anında ifa</strong> edilen bir hizmet/gayrimaddi mal
        niteliğinde olduğundan, Mesafeli Sözleşmeler Yönetmeliği md. 15 uyarınca, açık onayınızla
        ifasına başlanmasıyla birlikte <strong>cayma hakkı kullanılamaz</strong>. Ayrıntı için{' '}
        <a href="/legal/iptal-iade">İptal / İade &amp; Cayma Koşulları</a>.
      </p>

      <h3>6. Şikâyet ve Uyuşmazlık</h3>
      <p>
        Talep ve şikâyetlerinizi {COMPANY.email} adresine iletebilirsiniz. Uyuşmazlıklarda, ilgili
        parasal sınırlara göre Tüketici Hakem Heyetleri veya Tüketici Mahkemeleri yetkilidir.
      </p>
    </LegalArticle>
  );
}
