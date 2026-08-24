import { LegalArticle } from '../../../../components/LegalArticle';

export const metadata = { title: 'Sorumluluk Reddi — CyberTestify', alternates: { canonical: '/legal/sorumluluk-reddi' } };

export default function Page() {
  return (
    <LegalArticle title="Sorumluluk Reddi (Disclaimer)">
      <h3>Hizmetin Niteliği</h3>
      <p>
        CyberTestify, yalnızca sahipliği/yetkisi doğrulanmış alan adlarına yönelik <strong>pasif
        (saldırgan olmayan)</strong> bir güvenlik <strong>ön-değerlendirmesi</strong> sunar. Bu hizmet
        resmi bir sızma testi, uyumluluk denetimi (PCI-DSS ASV, ISO 27001, KVKK uyum denetimi vb.)
        veya akredite bir test <strong>değildir</strong> ve bunların yerine geçmez.
      </p>

      <h3>Yapay Zeka Üretimi ve Doğruluk</h3>
      <p>
        Raporlar yapay zeka tabanlı otomatik bir ajan tarafından üretilir. Tespitler yardımcı
        niteliktedir; <strong>yanlış pozitif veya yanlış negatif</strong> içerebilir. Olgusal
        ifadeler, bağımsız olarak doğrulanmadan kritik kararlara esas alınmamalıdır.
      </p>

      <h3>Kapsam Sınırı</h3>
      <p>
        Değerlendirme yalnızca doğrulanan hostname ve pasif yöntemlerle sınırlıdır. İç ağ,
        segmentasyon, kimlik doğrulamalı testler, aktif istismar ve sızma testi kapsam dışıdır. Tüm
        güvenlik açıklarının tespit edildiği garanti edilmez.
      </p>

      <h3>Sorumluluk</h3>
      <p>
        Bulguların doğrulanması, önceliklendirilmesi ve giderilmesi tamamen kullanıcının
        sorumluluğundadır. Yürürlükteki mevzuatın izin verdiği azami ölçüde, CyberTestify hizmetin
        kullanımından doğan dolaylı/arızi zararlardan sorumlu değildir.
      </p>

      <h3>Yetkilendirme</h3>
      <p>
        Kullanıcı, yalnızca sahibi/yetkilisi olduğu hedefler için tarama talep etmekle yükümlüdür.
        Yetkisiz taramalardan doğan tüm hukuki ve cezai sorumluluk kullanıcıya aittir.
      </p>
    </LegalArticle>
  );
}
