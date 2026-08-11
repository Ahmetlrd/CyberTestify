// (SEO/AEO) /llms.txt — AI asistanlarına siteyi özetleyen kısa, dürüst harita.
// Not: 6 aktif paket PentAGI/otonom pentest DEĞİL; deterministik kontroller + hafif yapay zekâ destekli
// analiz/öneriler. "Otonom" yalnız gelecekteki (Yakında) kurumsal hizmet için geçerlidir.
export const dynamic = 'force-static';

const BODY = `# CyberTestify

> Yapay zekâ destekli, otomatik web sitesi güvenlik ön-değerlendirme hizmeti. Yalnızca sahipliği DNS ile
> doğrulanmış alan adlarına karşı çalışır. Resmî bir sızma testi/denetim ya da sertifikasyon YERİNE GEÇMEZ.

## Ne yapar
- Deterministik güvenlik kontrolleri (dış yüzey/yapılandırma, keşif, uyum hazırlığı, kimlik-doğrulamalı kontroller).
- İki kontrolde hafif, yapay zekâ destekli analiz (tek LLM danışma çağrısı) ve bulgular için yapay zekâ destekli çözüm önerileri.
- "Kanıtla, istismar etme" ilkesi: açıklar gözlemlenir/kanıtlanır; veri çekilmez, sistem zarar görmez veya kesintiye uğratılmaz.

## Ne DEĞİLDİR
- Otonom/sınırsız bir sızma testi değildir (aktif paketler için).
- Resmî ASV/QSA denetimi veya bir uyum sertifikası değildir.

## Paketler (özet)
- Basit Tarama — hızlı ön izleme.
- Dış Yüzey & Yapılandırma, Keşif, Uyum Hazırlığı, Aktif Doğrulama, Tam Kapsamlı Pentest (kimlik-doğrulamalı) kombine paketleri.
- Elit Otonom Pentest (Kurumsal) — Yakında; kuruma özel teklif.

## Önemli sayfalar
- Ana sayfa: https://cybertestify.com/tr
- Paketler & fiyatlar: https://cybertestify.com/tr/packages
- Blog: https://cybertestify.com/blog
- Hakkımızda: https://cybertestify.com/hakkimizda
- İletişim: https://cybertestify.com/iletisim

## İletişim
- E-posta: support@cybertestify.com
`;

export function GET() {
  return new Response(BODY, {
    headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'public, max-age=3600' },
  });
}
