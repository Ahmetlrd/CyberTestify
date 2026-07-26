import { DEFAULT_REGION, isRegionCode, type RegionCode } from '../config/regions';

/** Tarayıcıda 'region' cookie'sini oku (yoksa varsayılan). Client-side. */
export function readRegionCookie(): RegionCode {
  if (typeof document === 'undefined') return DEFAULT_REGION;
  const m = document.cookie.match(/(?:^|;\s*)region=([^;]+)/);
  const code = m?.[1];
  return isRegionCode(code) ? code : DEFAULT_REGION;
}
