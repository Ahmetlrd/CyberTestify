import Link from 'next/link';

export default function HomePage() {
  return (
    <main>
      <h1>Kendi Sitenizi Test Edin</h1>
      <p>
        Sitenizin sahipliğini doğrulayın, hazır tarama paketlerinden birini seçin, şifreli
        güvenlik raporunuzu alın. Sektörü bilmenize gerek yok — teknik detayları biz hallederiz.
      </p>
      <ol>
        <li>Site sahipliğinizi DNS kaydıyla doğrulayın</li>
        <li>Tarama paketinizi seçip ödeyin</li>
        <li>Şifreli raporunuzu indirin</li>
      </ol>
      <p>
        <Link href="/register">Başla →</Link>
        {'  '}
        <span style={{ color: '#666' }}>
          Zaten hesabınız var mı? <Link href="/login">Giriş yap</Link>
        </span>
      </p>
      <p style={{ fontSize: 13, color: '#666' }}>
        Yalnızca sahipliğini doğruladığınız domain&apos;lere karşı tarama yapılır. Kapsam dışı
        hedeflere erişim kesinlikle yasaktır.
      </p>
    </main>
  );
}
