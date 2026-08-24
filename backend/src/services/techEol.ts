// ============================================================================
// EOL / ESKİ YAZILIM SÜRÜMÜ TESPİTİ (pasif — sunucu/teknoloji imzasından)
// ----------------------------------------------------------------------------
// Sunucu (Server) / X-Powered-By / <meta generator> gibi PASİF olarak ifşa edilen
// GERÇEK sürüm imzalarından, KONSERVATİF ve statik bir eşik listesiyle "artık
// desteklenmeyen (EOL) / güncel olmayan" yazılımı bir BULGU olarak çıkarır.
// UYDURMA YOK: yalnız gerçekten yakalanan major.minor(.patch) sürümüne dayanır,
// CVE numarası atmaz. CWE-1104 · OWASP A06:2021 (Vulnerable & Outdated Components).
//
// Yanlış-pozitiften kaçınmak için SADECE net vakalar işaretlenir (ör. PHP <8 kesin
// EOL). Desteklenen bir dalın (Apache 2.4) yalnız ÇOK eski bir yaması "güncel değil"
// (Orta) sayılır; EOL denmez.
//
// LOCALE: sev makine-değeri HER ZAMAN 'Yüksek'|'Orta' kalır (çağıranlar bununla
// dallanır); yalnız bulgu/aciklama metni locale'e göre üretilir. 'de' dışı → Türkçe.
// ============================================================================

export type EolFinding = { bulgu: string; sev: 'Yüksek' | 'Orta'; aciklama: string };

const CWE_TR = 'CWE-1104 · OWASP A06:2021 (Güncel Olmayan/Savunmasız Bileşenler)';
const CWE_DE = 'CWE-1104 · OWASP A06:2021 (Veraltete/Verwundbare Komponenten)';

// PASİF sürüm imzalarından (verilen string dizisi: "Sunucu: Apache/2.4.25 (Debian)",
// "X-Powered-By: PHP/7.1.26", "<meta generator> WordPress 5.2" vb.) EOL/eski bulgular.
export function detectOutdatedSoftware(techStrings: string[], locale: string = 'tr'): EolFinding[] {
  const de = locale === 'de';
  const CWE = de ? CWE_DE : CWE_TR;
  const joined = techStrings.join('  ');
  const out: EolFinding[] = [];

  const bulguEol = (ver: string) => de
    ? `Veraltete/nicht mehr unterstützte Softwareversion wird offengelegt (${ver} — EOL)`
    : `Eski/desteksiz yazılım sürümü ifşa ediliyor (${ver} — EOL)`;
  const bulguOld = (ver: string, note: { tr: string; de: string }) => de
    ? `Nicht aktuelle Softwareversion wird offengelegt (${ver} — ${note.de})`
    : `Güncel olmayan yazılım sürümü ifşa ediliyor (${ver} — ${note.tr})`;

  // --- PHP ---
  const php = joined.match(/php\/(\d+)\.(\d+)(?:\.(\d+))?/i);
  if (php) {
    const maj = +php[1], min = +php[2];
    const ver = `PHP/${php[1]}.${php[2]}${php[3] ? '.' + php[3] : ''}`;
    if (maj < 8) {
      out.push({ bulgu: bulguEol(ver), sev: 'Yüksek',
        aciklama: de
          ? `Die PHP-${maj}.x-Serie wird offiziell nicht mehr unterstützt (Sicherheitsupdates für 7.x endeten Ende 2022). Zahlreiche bekannte Sicherheitslücken bleiben ungepatcht. ${CWE}. Lösung: Auf eine aktuelle, unterstützte PHP-Version (8.2+) aktualisieren; die Versionssignatur verbergen (expose_php=Off).`
          : `PHP ${maj}.x serisi resmen desteklenmiyor (7.x güvenlik güncellemeleri 2022 sonunda bitti). Bilinen çok sayıda güvenlik açığı yamasız kalır. ${CWE}. Çözüm: güncel ve desteklenen bir PHP sürümüne (8.2+) yükseltin; sürüm imzasını gizleyin (expose_php=Off).` });
    } else if (maj === 8 && min <= 1) {
      out.push({ bulgu: bulguOld(ver, { tr: 'destek bitmiş', de: 'Support beendet' }), sev: 'Orta',
        aciklama: de
          ? `Der Sicherheitssupport für PHP 8.${min} ist beendet. ${CWE}. Lösung: Auf eine unterstützte PHP-Version (8.2+) aktualisieren und die Versionssignatur verbergen.`
          : `PHP 8.${min} güvenlik desteği sona ermiştir. ${CWE}. Çözüm: desteklenen bir PHP sürümüne (8.2+) yükseltin ve sürüm imzasını gizleyin.` });
    }
  }

  // --- Apache httpd ---
  const ap = joined.match(/apache\/(\d+)\.(\d+)(?:\.(\d+))?/i);
  if (ap) {
    const maj = +ap[1], min = +ap[2], patch = ap[3] != null ? +ap[3] : null;
    const ver = `Apache/${ap[1]}.${ap[2]}${ap[3] ? '.' + ap[3] : ''}`;
    if (maj < 2 || (maj === 2 && (min === 0 || min === 2))) {
      out.push({ bulgu: bulguEol(ver), sev: 'Yüksek',
        aciklama: de
          ? `Die Apache-httpd-Serie ${maj}.${min} ist außer Betrieb (EOL) und erhält keine Sicherheitsupdates mehr. ${CWE}. Lösung: Auf den aktuellen Patch der unterstützten 2.4-Serie wechseln; die Versionssignatur verbergen (ServerTokens Prod).`
          : `Apache httpd ${maj}.${min} serisi kullanım dışıdır (EOL) ve güvenlik güncellemesi almaz. ${CWE}. Çözüm: desteklenen 2.4 serisinin güncel yamasına geçin; sürüm imzasını gizleyin (ServerTokens Prod).` });
    } else if (maj === 2 && min === 4 && patch != null && patch < 52) {
      out.push({ bulgu: bulguOld(ver, { tr: 'çok eski yama', de: 'sehr alter Patchstand' }), sev: 'Orta',
        aciklama: de
          ? `Die Apache-2.4-Serie wird zwar unterstützt, ${ver} ist jedoch ein sehr alter Patchstand; zwischenzeitliche Sicherheitspatches scheinen nicht eingespielt zu sein. ${CWE}. Lösung: Auf den aktuellen Patch der 2.4-Serie aktualisieren; die Versionssignatur verbergen (ServerTokens Prod).`
          : `Apache 2.4 serisi desteklenmekle birlikte ${ver} çok eski bir yama düzeyidir; aradaki güvenlik yamaları uygulanmamış görünüyor. ${CWE}. Çözüm: 2.4 serisinin güncel yamasına yükseltin; sürüm imzasını gizleyin (ServerTokens Prod).` });
    }
  }

  // --- nginx (konservatif: yalnız çok eski) ---
  const ng = joined.match(/nginx\/(\d+)\.(\d+)(?:\.(\d+))?/i);
  if (ng) {
    const maj = +ng[1], min = +ng[2];
    const ver = `nginx/${ng[1]}.${ng[2]}${ng[3] ? '.' + ng[3] : ''}`;
    if (maj === 1 && min < 18) {
      out.push({ bulgu: bulguOld(ver, { tr: 'eski', de: 'veraltet' }), sev: 'Orta',
        aciklama: de
          ? `${ver} ist eine veraltete nginx-Version; zwischenzeitliche Sicherheitspatches können fehlen. ${CWE}. Lösung: Auf die aktuelle stabile nginx-Version aktualisieren; die Versionssignatur verbergen (server_tokens off).`
          : `${ver} eski bir nginx sürümüdür; aradaki güvenlik yamaları eksik olabilir. ${CWE}. Çözüm: güncel kararlı nginx sürümüne yükseltin; sürüm imzasını gizleyin (server_tokens off).` });
    }
  }

  return out;
}
