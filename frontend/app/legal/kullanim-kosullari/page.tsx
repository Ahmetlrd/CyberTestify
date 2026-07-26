import { LegalArticle } from '../../../components/LegalArticle';
import { COMPANY } from '../../../lib/company';

export const metadata = { title: 'Kullanım Koşulları — CyberTestify' };

export default function Page() {
  return (
    <LegalArticle title="Kullanım Koşulları">
      <p>
        Bu Kullanım Koşulları, {COMPANY.legalName} ({COMPANY.brand}, &quot;Hizmet Sağlayıcı&quot;)
        tarafından {COMPANY.domain} üzerinden sunulan güvenlik ön-değerlendirme hizmetinin
        kullanımını düzenler. Hizmeti kullanarak bu koşulları kabul etmiş sayılırsınız.
      </p>

      <h3>1. Hizmetin Tanımı</h3>
      <p>
        Hizmet; kullanıcının <strong>sahipliğini/yetkisini doğruladığı kendi alan adına</strong>
        yönelik, <strong>pasif (saldırgan olmayan)</strong> otomatik bir güvenlik ön-değerlendirmesi
        yapar ve şifreli bir rapor üretir. Hizmet, resmi bir sızma testi, uyumluluk denetimi veya
        akredite tarama (ASV/QSA vb.) <strong>değildir</strong> ve bunların yerine geçmez.
      </p>

      <h3>2. Kullanıcının Yükümlülükleri</h3>
      <ul>
        <li>Yalnızca <strong>münhasır sahibi olduğunuz veya yasal olarak yetkili olduğunuz</strong> alan adları için tarama talep edebilirsiniz.</li>
        <li>Paylaşımlı hosting/üçüncü taraf altyapıda barınan hedefler için, ilgili altyapı sağlayıcısının da izninin gerekebileceğini kabul edersiniz.</li>
        <li>Hizmeti hukuka aykırı, yetkisiz erişim veya üçüncü kişilere zarar amacıyla kullanmayacağınızı taahhüt edersiniz.</li>
        <li>Hesap güvenliğinizden ve giriş bilgilerinizin gizliliğinden siz sorumlusunuz.</li>
      </ul>

      <h3>3. Yetkisiz Kullanım Yasağı</h3>
      <p>
        Yetkiniz olmayan sistemlere tarama talebi, TCK md. 243-245 kapsamında suç teşkil edebilir.
        Bu tür taleplerden doğan tüm hukuki/cezai sorumluluk kullanıcıya aittir; Hizmet Sağlayıcı
        gerekli hallerde yetkili mercilerle iş birliği yapar ve hesabı askıya alabilir.
      </p>

      <h3>4. Yapay Zeka ve Doğruluk</h3>
      <p>
        Raporlar yapay zeka tabanlı otomatik bir ajan tarafından üretilir; yardımcı niteliktedir ve
        olgusal ifadeler bağımsız olarak doğrulanmadan karar alınarak kullanılmamalıdır. Bulguların
        eksiksizliği veya yanlış pozitif/negatif içermemesi garanti edilmez.
      </p>

      <h3>5. Sorumluluğun Sınırlandırılması</h3>
      <p>
        Hizmet &quot;olduğu gibi&quot; sunulur. Yürürlükteki mevzuatın izin verdiği azami ölçüde,
        Hizmet Sağlayıcı dolaylı/arızi zararlardan sorumlu değildir; toplam sorumluluk ilgili sipariş
        bedeliyle sınırlıdır. Ayrıntı için <a href="/legal/sorumluluk-reddi">Sorumluluk Reddi</a>.
      </p>

      <h3>6. Fikri Mülkiyet</h3>
      <p>Site içeriği ve yazılımına ilişkin haklar Hizmet Sağlayıcı&apos;ya veya lisans verenlerine aittir. Rapor içeriği ilgili müşteriye sunulur.</p>

      <h3>7. Değişiklik ve Uygulanacak Hukuk</h3>
      <p>
        Hizmet Sağlayıcı bu koşulları güncelleyebilir; güncel sürüm sitede yayımlanır. Uyuşmazlıklarda
        Türk hukuku uygulanır; tüketici işlemlerinde Tüketici Hakem Heyetleri ve Tüketici Mahkemeleri
        yetkilidir.
      </p>
    </LegalArticle>
  );
}
