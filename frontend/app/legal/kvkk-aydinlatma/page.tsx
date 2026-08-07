import { LegalArticle } from '../../../components/LegalArticle';
import { COMPANY } from '../../../lib/company';

export const metadata = { title: 'KVKK Aydınlatma Metni — CyberTestify' };

export default function Page() {
  return (
    <LegalArticle title="Kişisel Verilerin İşlenmesine İlişkin Aydınlatma Metni">
      <p>
        Bu metin, 6698 sayılı Kişisel Verilerin Korunması Kanunu (&quot;KVKK&quot;) md. 10 kapsamında,
        veri sorumlusu sıfatıyla <strong>{COMPANY.legalName}</strong> ({COMPANY.brand}) tarafından
        hazırlanmıştır. Adres: {COMPANY.address}. E-posta: {COMPANY.email}. KEP: {COMPANY.kep}.
      </p>

      <h3>1. İşlenen Kişisel Veriler</h3>
      <ul>
        <li><strong>Kimlik/İletişim:</strong> e-posta adresi</li>
        <li>
          <strong>İşlem güvenliği:</strong> parola (yalnızca bcrypt ile özetlenmiş biçimde saklanır —
          ham parola tutulmaz), oturum/IP adresi, log kayıtları
        </li>
        <li>
          <strong>Müşteri işlem/hedef verisi:</strong> doğrulanan alan adı (hostname), DNS doğrulama
          kaydı, tarama parametreleri ve rapor içeriği
        </li>
        <li>
          <strong>Finans:</strong> ödemeye ilişkin veriler; ödeme PCI-DSS uyumlu ödeme kuruluşu
          <strong> iyzico</strong> üzerinden alınır, kart verisi sistemlerimizde saklanmaz
        </li>
      </ul>

      <h3>2. İşleme Amaçları</h3>
      <p>
        Üyelik ve hesap yönetimi; alan adı sahipliğinin DNS ile doğrulanması; müşterinin yetki verdiği
        kendi alan adına yönelik <strong>pasif güvenlik taramasının</strong> yürütülmesi; rapor üretimi
        ve tek kullanımlık erişim kodunun e-posta ile iletilmesi; ödeme/faturalandırma; bilgi
        güvenliği, kötüye kullanım/dolandırıcılık önleme; vergi ve log tutma gibi yasal
        yükümlülüklerin yerine getirilmesi.
      </p>

      <h3>3. Hukuki Sebepler (md. 5)</h3>
      <ul>
        <li>Üyelik, e-posta, parola hash&apos;i, alan adı doğrulama, tarama hizmeti → md. 5/2-c (sözleşmenin ifası)</li>
        <li>IP/log, ödeme ve fatura kayıtları → md. 5/2-ç (hukuki yükümlülük) ve md. 5/2-f (meşru menfaat)</li>
      </ul>

      <h3>4. Aktarılan Alıcılar</h3>
      <ul>
        <li><strong>iyzico</strong> — ödeme işleminin gerçekleştirilmesi (yurt içi)</li>
        <li>
          <strong>Anthropic, PBC (ABD)</strong> — self-hosted PentAGI aracılığıyla tarama komutlarının
          yapay zeka ile işlenmesi (<strong>yurt dışı aktarım</strong>). Bu aktarım, sipariş sırasında
          ayrıca vereceğiniz <strong>açık rızanızla</strong> (KVKK m. 9) gerçekleştirilir. Rıza vermezseniz
          tarama hizmeti sunulamaz. (Sistemde tarama komutlarını işleyen tek yapay zeka sağlayıcısı
          Anthropic’tir.)
        </li>
        <li>
          <strong>Brevo (Sendinblue, AB/Fransa)</strong> — işlem/bilgilendirme e-postalarının (sipariş,
          rapor, doğrulama kodu) gönderilmesi; yalnızca e-posta adresiniz aktarılır (yurt dışı; hizmetin
          ifası kapsamında)
        </li>
        <li>
          <strong>Google LLC (ABD)</strong> — yalnızca “Google ile giriş”i tercih ederseniz, kimlik
          doğrulaması için (yurt dışı; kendi tercihinizle)
        </li>
        <li>Yetkili kamu kurum/kuruluşları (mevzuat gereği, talep halinde)</li>
      </ul>

      <h3>5. Toplama Yöntemi</h3>
      <p>Veriler; web sitesi formları, DNS sorguları, tarama süreçleri ve ödeme akışı üzerinden elektronik ortamda otomatik/kısmen otomatik yollarla toplanır.</p>

      <h3>6. Saklama Süreleri</h3>
      <p>
        Rapor içeriği kısa ve tanımlı bir süre (varsayılan 30 gün) sonunda silinir. Ödeme/sipariş
        kayıtları ise ticari ve vergi mevzuatı (TTK/VUK) gereği daha uzun süre (tipik 10 yıl)
        saklanır. IP/log kayıtları güvenlik amaçlı asgari süre boyunca tutulur.
      </p>

      <h3>7. İlgili Kişinin Hakları (md. 11)</h3>
      <p>
        KVKK md. 11 uyarınca; verilerinizin işlenip işlenmediğini öğrenme, bilgi talep etme, amacına
        uygun kullanılıp kullanılmadığını öğrenme, aktarıldığı üçüncü kişileri bilme, düzeltilmesini/
        silinmesini isteme, otomatik analiz sonucu aleyhinize çıkan sonuca itiraz etme ve zararın
        giderilmesini talep etme haklarına sahipsiniz. Başvurularınızı {COMPANY.email} adresine
        iletebilirsiniz; talepler en geç <strong>30 gün</strong> içinde yanıtlanır.
      </p>
    </LegalArticle>
  );
}
