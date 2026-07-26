import { LegalArticle } from '../../../components/LegalArticle';
import { COMPANY } from '../../../lib/company';

export const metadata = { title: 'Gizlilik Politikası — CyberTestify' };

export default function Page() {
  return (
    <LegalArticle title="Gizlilik Politikası">
      <p>
        {COMPANY.legalName} ({COMPANY.brand}) olarak gizliliğinize önem veriyoruz. Bu politika,
        hangi verileri neden işlediğimizi ve nasıl koruduğumuzu özetler. Kişisel verilere ilişkin
        ayrıntılı bilgilendirme için <a href="/legal/kvkk-aydinlatma">KVKK Aydınlatma Metni</a>&apos;ni
        inceleyin.
      </p>

      <h3>Topladığımız Veriler</h3>
      <p>E-posta, parola (yalnızca hash), IP/log kayıtları, doğrulanan alan adı, tarama parametreleri ve rapor içeriği, ödeme işlem bilgileri (iyzico üzerinden).</p>

      <h3>Kullanım Amacı</h3>
      <p>Hesap yönetimi, alan adı doğrulama, taramanın yürütülmesi, rapor teslimi, ödeme/faturalandırma, güvenlik ve yasal yükümlülükler.</p>

      <h3>Paylaşım</h3>
      <p>
        Veriler yalnızca hizmetin gerektirdiği ölçüde paylaşılır: <strong>iyzico</strong> (ödeme,
        yurt içi) ve <strong>Anthropic/ABD</strong> (tarama komutlarının işlenmesi, yurt dışı — uygun
        güvence ile). Verilerinizi pazarlama amacıyla üçüncü kişilere satmayız.
      </p>

      <h3>Güvenlik</h3>
      <p>
        Rapor içeriği AES-256-GCM ile şifreli saklanır ve yalnızca size özel tek kullanımlık erişim
        koduyla çözülebilir. Parolalar bcrypt ile özetlenir. İletişim TLS ile şifrelenir. Ham tarama
        verisi rapor üretilir üretilmez altyapıdan silinir.
      </p>

      <h3>Saklama ve İmha</h3>
      <p>Rapor içeriği kısa süre (varsayılan 30 gün) sonunda silinir; sipariş/ödeme kayıtları yasal süreler boyunca saklanır. Ayrıntı için KVKK Aydınlatma Metni.</p>

      <h3>Çerezler</h3>
      <p>Yalnızca hizmetin çalışması için gerekli teknik çerezler kullanılır. Bkz. <a href="/legal/cerez">Çerez Politikası</a>.</p>

      <h3>İletişim</h3>
      <p>Sorularınız ve talepleriniz için: {COMPANY.email}</p>
    </LegalArticle>
  );
}
