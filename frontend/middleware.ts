import { NextResponse, type NextRequest } from 'next/server';
import { DEFAULT_REGION, isRegionCode, isVisibleRegion } from './config/regions';

const YEAR = 60 * 60 * 24 * 365;

/** Ziyaretçi için en uygun bölgeyi tespit et: cookie > coğrafi header > dil > tr. */
function pickRegion(req: NextRequest): string {
  // GEÇİCİ: Yalnızca GÖRÜNÜR bölgeler seçilebilir (şu an sadece tr). us/ae kapalı olduğu
  // için cookie/geo/dil sinyalleri görünür değilse DEFAULT_REGION'a (tr) düşer.
  const cookie = req.cookies.get('region')?.value;
  if (isVisibleRegion(cookie)) return cookie;

  // Vercel/Cloudflare gibi platformlar coğrafi konumu header olarak verir.
  const country = (
    req.headers.get('x-vercel-ip-country') ||
    req.headers.get('cf-ipcountry') ||
    ''
  ).toLowerCase();
  if (isVisibleRegion(country)) return country;

  // Dil sinyali: Turkce tarayici -> tr; diger diller de (us/ae kapaliyken) tr'ye duser.
  const al = (req.headers.get('accept-language') ?? '').toLowerCase();
  if (al.includes('tr')) return 'tr';
  if (al.trim() && isVisibleRegion('us')) return 'us'; // us acilinca otomatik geri gelir

  return DEFAULT_REGION;
}

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const seg = pathname.split('/')[1];

  // Server component'lerin (root layout) hangi path'te olduklarini bilebilmesi
  // icin path'i request header olarak tasi (/admin'de musteri Nav/Footer gizlenir).
  const headers = new Headers(req.headers);
  headers.set('x-pathname', pathname);
  const pass = () => NextResponse.next({ request: { headers } });

  // Bölge önekli GÖRÜNÜR rota (/tr): tercihi cookie'ye yaz, geç.
  if (isVisibleRegion(seg)) {
    const res = pass();
    res.cookies.set('region', seg, { path: '/', maxAge: YEAR });
    return res;
  }
  // (Almanya lansmanı — BLOG İSTİSNASI) /de henüz GÖRÜNMEZ ama /de/blog erişilebilir olmalı
  // (P5: boş "Bald verfügbar" sayfası). Bu yüzden /de/blog(/...) aşağıdaki /de -> /tr redirect'ine
  // TAKILMADAN geçer (cookie region'ı DEĞİŞTİRİLMEZ — ziyaretçinin bölgesi bozulmasın).
  if (seg === 'de' && (pathname === '/de/blog' || pathname.startsWith('/de/blog/'))) {
    return pass();
  }
  // (Almanya) Almanca yasal sayfalar (/de/legal/impressum|datenschutz|agb|widerruf) — /de görünmese
  // de erişilebilir olsun (inceleme/avukat). Taslak oldukları için sayfalar robots index:false.
  if (seg === 'de' && pathname.startsWith('/de/legal/')) {
    return pass();
  }
  // GEÇİCİ: Kapalı bölgeye doğrudan erişim (/us, /ae, görünmez /de) -> aynı yolu görünür bölgeyle (tr) ver.
  if (isRegionCode(seg)) {
    const rest = pathname.slice(seg.length + 1); // "/us/packages" -> "/packages"
    return NextResponse.redirect(new URL(`/${DEFAULT_REGION}${rest}`, req.url));
  }

  // Bölgeye özel (marketing) rotaları uygun bölgeye yönlendir.
  const region = pickRegion(req);
  if (pathname === '/') {
    // REDIRECT DEGIL REWRITE: apex kök '/' artik 307 yerine 200 + içerik döner.
    // Neden: iyzico gibi otomatik denetim botları 307'yi takip etmeyip "ulaşılamıyor"
    // diyebiliyordu (boş gövde). Rewrite ile URL '/' kalır ama /{bölge} sayfası
    // sunulur (locale tespiti + iki-domain korunur). Bölge tercihi yine cookie'ye yazılır.
    const res = NextResponse.rewrite(new URL(`/${region}`, req.url), { request: { headers } });
    res.cookies.set('region', region, { path: '/', maxAge: YEAR });
    return res;
  }
  if (pathname === '/packages') {
    return NextResponse.redirect(new URL(`/${region}/packages`, req.url));
  }
  // (COK-BOLGE) Legal sayfalar artik bolge-onekli (/{bolge}/legal/...). Eski cıplak /legal/* linkleri
  // (mail/bookmark/eski iç link) KIRILMASIN diye uygun bolgeye yonlendirilir.
  if (pathname === '/legal' || pathname.startsWith('/legal/')) {
    return NextResponse.redirect(new URL(`/${region}${pathname}`, req.url));
  }
  // (Cok-dilli blog) Eski cıplak /blog(/...) -> KALICI /tr/blog (301). Eski indeksli URL'ler/bağlantılar
  // kırılmasın; /tr/blog içerik/davranış aynı kalır. /de/blog yukarıda ayrıca ele alındı.
  if (pathname === '/blog' || pathname.startsWith('/blog/')) {
    return NextResponse.redirect(new URL(`/tr${pathname}`, req.url), 301);
  }

  // Uygulama/hukuki/statik/admin rotalar bölge-bağımsız — dokunma.
  return pass();
}

export const config = {
  // _next, api ve dosya uzantılı istekleri hariç tut.
  matcher: ['/((?!_next|api|.*\\..*).*)'],
};
