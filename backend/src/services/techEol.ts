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
// ============================================================================

export type EolFinding = { bulgu: string; sev: 'Yüksek' | 'Orta'; aciklama: string };

const CWE = 'CWE-1104 · OWASP A06:2021 (Güncel Olmayan/Savunmasız Bileşenler)';

// PASİF sürüm imzalarından (verilen string dizisi: "Sunucu: Apache/2.4.25 (Debian)",
// "X-Powered-By: PHP/7.1.26", "<meta generator> WordPress 5.2" vb.) EOL/eski bulgular.
export function detectOutdatedSoftware(techStrings: string[]): EolFinding[] {
  const joined = techStrings.join('  ');
  const out: EolFinding[] = [];

  // --- PHP ---
  const php = joined.match(/php\/(\d+)\.(\d+)(?:\.(\d+))?/i);
  if (php) {
    const maj = +php[1], min = +php[2];
    const ver = `PHP/${php[1]}.${php[2]}${php[3] ? '.' + php[3] : ''}`;
    if (maj < 8) {
      out.push({ bulgu: `Eski/desteksiz yazılım sürümü ifşa ediliyor (${ver} — EOL)`, sev: 'Yüksek',
        aciklama: `PHP ${maj}.x serisi resmen desteklenmiyor (7.x güvenlik güncellemeleri 2022 sonunda bitti). Bilinen çok sayıda güvenlik açığı yamasız kalır. ${CWE}. Çözüm: güncel ve desteklenen bir PHP sürümüne (8.2+) yükseltin; sürüm imzasını gizleyin (expose_php=Off).` });
    } else if (maj === 8 && min <= 1) {
      out.push({ bulgu: `Güncel olmayan yazılım sürümü ifşa ediliyor (${ver} — destek bitmiş)`, sev: 'Orta',
        aciklama: `PHP 8.${min} güvenlik desteği sona ermiştir. ${CWE}. Çözüm: desteklenen bir PHP sürümüne (8.2+) yükseltin ve sürüm imzasını gizleyin.` });
    }
  }

  // --- Apache httpd ---
  const ap = joined.match(/apache\/(\d+)\.(\d+)(?:\.(\d+))?/i);
  if (ap) {
    const maj = +ap[1], min = +ap[2], patch = ap[3] != null ? +ap[3] : null;
    const ver = `Apache/${ap[1]}.${ap[2]}${ap[3] ? '.' + ap[3] : ''}`;
    if (maj < 2 || (maj === 2 && (min === 0 || min === 2))) {
      out.push({ bulgu: `Eski/desteksiz yazılım sürümü ifşa ediliyor (${ver} — EOL)`, sev: 'Yüksek',
        aciklama: `Apache httpd ${maj}.${min} serisi kullanım dışıdır (EOL) ve güvenlik güncellemesi almaz. ${CWE}. Çözüm: desteklenen 2.4 serisinin güncel yamasına geçin; sürüm imzasını gizleyin (ServerTokens Prod).` });
    } else if (maj === 2 && min === 4 && patch != null && patch < 52) {
      out.push({ bulgu: `Güncel olmayan yazılım sürümü ifşa ediliyor (${ver} — çok eski yama)`, sev: 'Orta',
        aciklama: `Apache 2.4 serisi desteklenmekle birlikte ${ver} çok eski bir yama düzeyidir; aradaki güvenlik yamaları uygulanmamış görünüyor. ${CWE}. Çözüm: 2.4 serisinin güncel yamasına yükseltin; sürüm imzasını gizleyin (ServerTokens Prod).` });
    }
  }

  // --- nginx (konservatif: yalnız çok eski) ---
  const ng = joined.match(/nginx\/(\d+)\.(\d+)(?:\.(\d+))?/i);
  if (ng) {
    const maj = +ng[1], min = +ng[2];
    const ver = `nginx/${ng[1]}.${ng[2]}${ng[3] ? '.' + ng[3] : ''}`;
    if (maj === 1 && min < 18) {
      out.push({ bulgu: `Güncel olmayan yazılım sürümü ifşa ediliyor (${ver} — eski)`, sev: 'Orta',
        aciklama: `${ver} eski bir nginx sürümüdür; aradaki güvenlik yamaları eksik olabilir. ${CWE}. Çözüm: güncel kararlı nginx sürümüne yükseltin; sürüm imzasını gizleyin (server_tokens off).` });
    }
  }

  return out;
}
