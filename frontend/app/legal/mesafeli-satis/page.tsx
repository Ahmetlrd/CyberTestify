import { LegalArticle } from '../../../components/LegalArticle';
import { COMPANY } from '../../../lib/company';

export const metadata = { title: 'Mesafeli Satış Sözleşmesi — CyberTestify', alternates: { canonical: '/legal/mesafeli-satis' } };

export default function Page() {
  return (
    <LegalArticle title="Mesafeli Satış Sözleşmesi">
      <h3>1. Taraflar</h3>
      <p>
        <strong>Satıcı:</strong> {COMPANY.brand}, {COMPANY.email}.<br />
        <strong>Alıcı:</strong> Sipariş sırasında hesap bilgilerini giren kullanıcı (&quot;Tüketici&quot;).
      </p>

      <h3>2. Konu</h3>
      <p>
        Bu sözleşme, Tüketici&apos;nin {COMPANY.domain} üzerinden elektronik ortamda sipariş ettiği
        dijital güvenlik ön-değerlendirme hizmetinin satışı ve ifasına ilişkin tarafların hak ve
        yükümlülüklerini, 6502 sayılı Kanun ve Mesafeli Sözleşmeler Yönetmeliği uyarınca düzenler.
      </p>

      <h3>3. Sözleşme Konusu Hizmet ve Bedel</h3>
      <p>
        Hizmetin niteliği, kapsamı ve tüm vergiler dahil bedeli, sipariş ekranında ve{' '}
        <a href="/legal/on-bilgilendirme">Ön Bilgilendirme Formu</a>&apos;nda belirtildiği gibidir.
        Tüketici, sözleşmeyi kurmadan önce bu bilgileri edindiğini kabul eder.
      </p>

      <h3>4. İfa</h3>
      <p>
        Ödeme onayının ardından hizmet, Tüketici&apos;nin açık onayıyla anında ifa edilmeye başlanır.
        Rapor hazır olduğunda Tüketici&apos;nin panelinde erişime açılır; tek kullanımlık erişim kodu
        e-posta ile iletilir. Sözleşme ve ön bilgilendirmenin teyidi, kalıcı veri saklayıcısı
        (e-posta) ile Tüketici&apos;ye gönderilir.
      </p>

      <h3>5. Cayma Hakkı</h3>
      <p>
        Hizmet dijital/anında ifa edildiğinden, Yönetmelik md. 15 uyarınca ifasına başlandıktan sonra
        cayma hakkı kullanılamaz. Bkz. <a href="/legal/iptal-iade">İptal / İade &amp; Cayma</a>.
      </p>

      <h3>6. Tüketicinin Beyan ve Taahhütleri</h3>
      <p>
        Tüketici, tarama talep ettiği alan adının münhasır sahibi veya yasal yetkili temsilcisi
        olduğunu; yetkisi dışındaki hiçbir hedefe tarama talep etmeyeceğini kabul ve taahhüt eder.
      </p>

      <h3>7. Uyuşmazlık</h3>
      <p>
        Uyuşmazlıklarda Türk hukuku uygulanır; parasal sınırlara göre Tüketici Hakem Heyetleri veya
        Tüketici Mahkemeleri yetkilidir.
      </p>

      <h3>8. Yürürlük</h3>
      <p>Tüketici, sipariş ekranında bu sözleşmeyi onayladığında sözleşme kurulmuş ve yürürlüğe girmiş sayılır.</p>
    </LegalArticle>
  );
}
