// (SEO çok-bölge slug) Kurumsal sayfalar dosya sisteminde TR-slug klasöründe durur; EN/DE'de
// yerelleştirilmiş URL slug'ıyla sunulur (next.config afterFiles rewrite alias'ıyla). Canonical/hreflang,
// footer linkleri ve sitemap bu TEK haritadan üretilir → tutarlılık, uydurma yok.
export const CORP_SLUGS = {
  hakkimizda: { tr: 'hakkimizda', de: 'ueber-uns', en: 'about' },
  iletisim: { tr: 'iletisim', de: 'kontakt', en: 'contact' },
  'acik-kaynak': { tr: 'acik-kaynak', de: 'open-source', en: 'open-source' },
} as const;
export type CorpBaseSlug = keyof typeof CORP_SLUGS;
const langOf = (regionCode: string): 'tr' | 'de' | 'en' =>
  regionCode === 'de' ? 'de' : regionCode === 'en' ? 'en' : 'tr';
/** Bölge koduna göre yerelleştirilmiş URL slug'ı ('hakkimizda' + 'en' -> 'about'). */
export function corpSlug(base: CorpBaseSlug, regionCode: string): string {
  return CORP_SLUGS[base][langOf(regionCode)];
}
/** canonical alternates için hreflang haritası. */
export function corpLanguages(base: CorpBaseSlug, site: string): Record<string, string> {
  const m = CORP_SLUGS[base];
  return { tr: `${site}/tr/${m.tr}`, de: `${site}/de/${m.de}`, en: `${site}/en/${m.en}`, 'x-default': `${site}/tr/${m.tr}` };
}
