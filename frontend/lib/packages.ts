// PASİF / AKTİF paket sınıflandırması (frontend) — backend scanPackages.isActivePackage ile AYNI
// anlam. AKTİF = sisteme fiilen prob/payload gönderir (SQLi/XSS enjeksiyon, IDOR, login prob…) →
// DNS sahiplik doğrulaması ZORUNLU (çelik kapı). PASİF = yalnız dışarıdan GET/TLS gözlemi →
// doğrulama GEREKMEZ. Güvenli taraf: bilinmeyen/emin olunmayan key PASİF sayılır ama iki aktif
// bundle + aktif tekil üyeler AÇIKÇA listelenir (yanlış-pasif riski taşımayalım).
export const ACTIVE_PACKAGE_KEYS = new Set<string>([
  'bundle_active_verify',
  'bundle_full_pentest',
  'bundle_elite_autonomous',
  'authenticated_scan',
  'autonomous_pentest',
  'injection_verify',
  'idor_verify',
  'ssrf_verify',
  'file_upload_verify',
  'business_logic_verify',
  'race_massassign_verify',
  'rce_verify',
]);

export function isActivePackageKey(key?: string | null): boolean {
  return !!key && ACTIVE_PACKAGE_KEYS.has(key);
}
