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

  const al = (req.headers.get('accept-language') ?? '').toLowerCase();
  if (al.includes('tr')) return 'tr';
  if (al.includes('en')) return 'us';

  return DEFAULT_REGION;
}

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const seg = pathname.split('/')[1];

  // Zaten bölge önekli (/tr, /us, /ae): tercihi cookie'ye yaz, geç.
  if (isRegionCode(seg)) {
    const res = NextResponse.next();
    res.cookies.set('region', seg, { path: '/', maxAge: YEAR });
    return res;
  }

  // Bölgeye özel (marketing) rotaları uygun bölgeye yönlendir.
  const region = pickRegion(req);
  if (pathname === '/') {
    return NextResponse.redirect(new URL(`/${region}`, req.url));
  }
  if (pathname === '/packages') {
    return NextResponse.redirect(new URL(`/${region}/packages`, req.url));
  }

  // Uygulama/hukuki/statik rotalar bölge-bağımsız — dokunma.
  return NextResponse.next();
}

export const config = {
  // _next, api ve dosya uzantılı istekleri hariç tut.
  matcher: ['/((?!_next|api|.*\\..*).*)'],
};
