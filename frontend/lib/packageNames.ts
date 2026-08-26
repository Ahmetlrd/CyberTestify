// (ÇOK-DİLLİ paket adı) order.packageName siparişin OLUŞTURULDUĞU dilde gelir; görüntüleme bölgesi
// farklıysa yanlış dil görünür. packageKey'den GÖRÜNTÜLEME diline göre lokalize et; bilinmeyen key
// veya null → gelen packageName'e düş. (Backend bundles.ts displayName* ile birebir.)
const PKG_NAME: Record<string, { tr: string; de: string; en: string }> = {
  bundle_surface: { tr: 'Dış Yüzey & Yapılandırma Paketi', de: 'Paket Externe Angriffsfläche & Konfiguration', en: 'External Surface & Configuration Bundle' },
  bundle_recon: { tr: 'Keşif Paketi', de: 'Reconnaissance-Paket', en: 'Discovery Bundle' },
  bundle_compliance: { tr: 'Uyum Paketi', de: 'Compliance-Paket', en: 'Compliance Bundle' },
  bundle_active_verify: { tr: 'Aktif Doğrulama Paketi', de: 'Paket Aktive Verifikation', en: 'Active Verification Bundle' },
  bundle_full_pentest: { tr: 'Tam Kapsamlı Pentest Paketi', de: 'Umfassendes Pentest-Paket', en: 'Full-Scope Pentest Bundle' },
  bundle_elite_autonomous: { tr: 'Elit Otonom Pentest (Kurumsal)', de: 'Elite Autonomes Pentest (Enterprise)', en: 'Elite Autonomous Pentest (Enterprise)' },
};

export function localizedPackageName(packageKey: string | null | undefined, packageName: string | null | undefined, lang: 'tr' | 'de' | 'en'): string | null {
  const l = lang === 'de' ? 'de' : lang === 'en' ? 'en' : 'tr';
  return (packageKey && PKG_NAME[packageKey]?.[l]) || packageName || null;
}
