import { NextResponse, type NextRequest } from 'next/server';
import { DEFAULT_REGION, isRegionCode } from './config/regions';

const YEAR = 60 * 60 * 24 * 365;

/** Ziyaretçi için en uygun bölgeyi tespit et: cookie > coğrafi header > dil > tr. */
function pickRegion(req: NextRequest): string {
  const cookie = req.cookies.get('region')?.value;
  if (isRegionCode(cookie)) return cookie;

  // Vercel/Cloudflare gibi platformlar coğrafi konumu header olarak verir.
  const country = (
    req.headers.get('x-vercel-ip-country') ||
    req.headers.get('cf-ipcountry') ||
    ''
  ).toLowerCase();
  if (isRegionCode(country)) return country;

  // Dil sinyali: YALNIZCA Turkce tarayici -> tr; diger TUM diller -> us (EN + USD).
  // (Geo-IP header'i bu altyapida (Caddy) gelmiyor; deterministik dil-tabanli kural.)
  const al = (req.headers.get('accept-language') ?? '').toLowerCase();
  if (al.includes('tr')) return 'tr';
  if (al.trim()) return 'us'; // herhangi bir (Turkce olmayan) dil sinyali -> EN

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

  // Zaten bölge önekli (/tr, /us, /ae): tercihi cookie'ye yaz, geç.
  if (isRegionCode(seg)) {
    const res = pass();
    res.cookies.set('region', seg, { path: '/', maxAge: YEAR });
    return res;
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

  // Uygulama/hukuki/statik/admin rotalar bölge-bağımsız — dokunma.
  return pass();
}

export const config = {
  // _next, api ve dosya uzantılı istekleri hariç tut.
  matcher: ['/((?!_next|api|.*\\..*).*)'],
};
