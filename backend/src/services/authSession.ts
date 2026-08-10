/**
 * (Tam Kapsamlı Pentest) OTURUM tipi + yardımcıları — authLogin.ts (FAZ B) ve activeVerifyEvidence.ts
 * (FAZ C) burayı paylaşır (import döngüsünü kırar). AuthSession ŞİFRE İÇERMEZ: yalnız cookie/bearer.
 */

export type CookieFlag = { name: string; secure: boolean; httpOnly: boolean; sameSite: string | null };

export type AuthSession = {
  method: 'api' | 'form';
  loginUrl: string;
  cookie?: string;                 // "name=value; name2=value2" (Cookie header — flag'siz)
  bearer?: string;                 // Authorization: Bearer <...>
  cookieFlags?: CookieFlag[];      // login yanıtındaki Set-Cookie bayrak analizi (FAZ C — çerez güvenliği)
  acquiredAt: number;
};

/** Bir ham Set-Cookie satırını isim + güvenlik bayraklarına ayrıştır (değer TUTULMAZ). */
export function parseSetCookie(line: string): CookieFlag {
  const name = line.split('=')[0].trim();
  const lower = line.toLowerCase();
  const sm = line.match(/;\s*samesite\s*=\s*([a-z]+)/i);
  return {
    name,
    secure: /;\s*secure(\s*;|\s*$)/i.test(line) || /;\s*secure\b/i.test(lower),
    httpOnly: /;\s*httponly\b/i.test(lower),
    sameSite: sm ? sm[1] : null,
  };
}

/** İsteklere oturumu uygula (Cookie/Authorization). Kontroller (FAZ C) probe'larında bunu kullanır. */
export function applyAuthHeaders(headers: Record<string, string>, s: AuthSession): Record<string, string> {
  const h = { ...headers };
  if (s.cookie) h['cookie'] = s.cookie;
  if (s.bearer) h['authorization'] = `Bearer ${s.bearer}`;
  return h;
}
