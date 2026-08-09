/**
 * (Keşif Paketi — bundle_recon) DETERMINISTIK BIRLESIK RAPOR URETICISI.
 *
 * subdomain_takeover + api_discovery + cms_cve — ucu de KOD-toplanmis kanittan (reconEvidence.ts)
 * uretilir; PentAGI ajani HIC calismaz. CVE bilgisi yalnizca NVD'nin yapisal cevabindan gelir,
 * Turkce rapor cumlesini HER ZAMAN kod yazar. Cikti bundle_surface/bundle_compliance ile ayni
 * bicimde: TEK Yonetici Ozeti + TEK genel risk rozeti (worst-case + birikimli) + 3 alan + TEK
 * "AI Cozum Onerileri" (kilit mekanizmasiyla). generateBundleReconReport { findings, fixText } | null doner.
 */
import { collectReconEvidence, type ReconEvidence, type SubEvidence, type ApiEvidence, type CmsEvidence } from './reconEvidence.js';

const RISK_WORD = { low: 'Düşük', medium: 'Orta', 'medium-high': 'Orta-Yüksek', high: 'Yüksek' } as const;
type Level = 'low' | 'medium' | 'medium-high' | 'high';
function levelRank(l: Level): number { return l === 'high' ? 3 : l === 'medium-high' ? 2 : l === 'medium' ? 1 : 0; }

type Area = { title: string; level: Level; headline: string; body: string; fixText: string };

const CAUTION_CVE = '> **Not:** Aşağıdaki CVE listesi, tespit edilen sürümle NVD (NIST Ulusal Zafiyet Veritabanı) üzerinden **otomatik eşlenen** bilinen zafiyetlerdir; sürümünüz için sömürülebilir oldukları **doğrulanmamıştır** ve bir kısmı eklenti/tema kaynaklı olabilir. Kesin durum için güncelleme + hedefli doğrulama önerilir.';

// ======================================================================================
// 1) subdomain_takeover
// ======================================================================================
function buildSubArea(ev: SubEvidence): Area {
  const confirmed = ev.dangling.filter((d) => d.confidence === 'confirmed');
  const suspected = ev.dangling.filter((d) => d.confidence === 'suspected');
  let level: Level = 'low';
  if (confirmed.length) level = 'high';
  else if (suspected.length) level = 'medium-high';

  const headline = confirmed.length
    ? `${confirmed.length} devralınabilir (dangling) alt domain tespit edildi`
    : suspected.length
      ? `${suspected.length} şüpheli alt domain — manuel doğrulama gerekli`
      : ev.total
        ? `${ev.total} alt domain görüldü; devralınabilir kayıt tespit edilmedi`
        : 'Sertifika şeffaflığı kayıtlarında alt domain görülmedi';

  const lines: string[] = [];
  lines.push(`Certificate Transparency (crt.sh / certSpotter) kayıtlarından **${ev.total}** benzersiz alt domain görüldü; bunlardan ${ev.resolved} tanesinin CNAME kaydı çözümlendi.`);
  lines.push('');

  if (confirmed.length || suspected.length) {
    lines.push('## DEVRALINABİLİR (DANGLING) ALT DOMAİNLER\n');
    lines.push('| Alt Domain | CNAME Hedefi | Servis | Durum | Açıklama |');
    lines.push('|-----------|--------------|--------|-------|----------|');
    for (const d of [...confirmed, ...suspected]) {
      lines.push(`| ${d.sub} | ${d.cname} | ${d.service} | ${d.confidence === 'confirmed' ? '⚠️ Doğrulandı' : 'Şüpheli'} | ${d.note} |`);
    }
    lines.push('');
    lines.push('> **Subdomain takeover riski:** Bir alt domain, artık size ait olmayan/terk edilmiş bir bulut kaynağına (CNAME) işaret ediyorsa, saldırgan o kaynağı kendi adına oluşturup alt domaininiz üzerinden içerik yayınlayabilir (oltalama, çerez/oturum çalma, marka istismarı). En yüksek öncelikli keşif bulgusudur.');
    lines.push('');
  } else {
    lines.push('Çözümlenen CNAME kayıtlarında, terk edilmiş bir buluta işaret eden **devralınabilir (dangling)** alt domain tespit edilmedi.');
    lines.push('');
  }

  if (ev.managedCnames.length) {
    lines.push('## YÖNETİLEN DIŞ SERVİS CNAME’LERİ (bilgi)\n');
    lines.push('Aşağıdaki alt domainler bilinen bir dış servise (CNAME) işaret ediyor ve şu an **canlı** görünüyor — risk değil, envanter bilgisidir:');
    lines.push('');
    for (const m of ev.managedCnames.slice(0, 15)) lines.push(`- **${m.sub}** → ${m.cname} (${m.service})`);
    lines.push('');
  }

  if (ev.total && ev.subdomains.length) {
    lines.push('## GÖRÜLEN ALT DOMAİNLER (örnekleme)\n');
    lines.push(ev.subdomains.map((s) => `- ${s}`).join('\n'));
    if (ev.total > ev.subdomains.length) lines.push(`\n_(+${ev.total - ev.subdomains.length} tane daha; tümü CT kayıtlarından pasif olarak elde edildi.)_`);
    lines.push('');
  }

  lines.push('> Kapsam: Yalnızca pasif kaynaklar (Certificate Transparency + gözlemlenebilir DNS). Alt domain brute-force / aktif tarama yapılmamıştır.');

  const fixText = confirmed.length || suspected.length
    ? '### Subdomain Takeover — düzeltme\n\n' +
      [...confirmed, ...suspected].map((d) => `- **${d.sub}** (${d.service}): Bu alt domain kullanılmıyorsa DNS’ten **CNAME kaydını silin**. Kullanılıyorsa, ${d.service} tarafında kaynağı **yeniden oluşturup sahiplenin** (claim), böylece kayıt boşta kalmaz.`).join('\n') +
      '\n\n- Genel önlem: Kullanılmayan alt domainleri düzenli olarak temizleyin; bulut kaynağı silmeden önce DNS kaydını kaldırın (kaldırma sırası önemli).'
    : '### Subdomain Takeover\n\nDevralınabilir alt domain tespit edilmedi. Alt domain envanterinizi düzenli gözden geçirin; kullanılmayan CNAME kayıtlarını silin.';

  return { title: 'Subdomain Takeover Taraması', level, headline, body: lines.join('\n'), fixText };
}

// ======================================================================================
// 2) api_discovery
// ======================================================================================
function buildApiArea(ev: ApiEvidence): Area {
  const spec = ev.spec;
  const sensitive = spec?.sensitive ?? [];
  const noAuthSensitive = sensitive.filter((s) => s.noAuth);
  let level: Level = 'low';
  if (noAuthSensitive.length) level = 'high';
  else if (spec && sensitive.length) level = 'medium-high';
  else if (spec || ev.reachable.length) level = 'medium';

  const headline = noAuthSensitive.length
    ? `${noAuthSensitive.length} hassas uç nokta kimlik doğrulamasız görünüyor`
    : spec && sensitive.length
      ? `Herkese açık API şeması + ${sensitive.length} hassas uç nokta`
      : spec
        ? `Herkese açık API şeması (${spec.endpointCount} uç nokta)`
        : ev.reachable.length
          ? `${ev.reachable.length} API dokümantasyon noktası herkese açık`
          : 'Herkese açık API/Swagger dokümantasyonu bulunamadı';

  const lines: string[] = [];
  if (ev.reachable.length) {
    lines.push('## ERİŞİLEBİLİR API NOKTALARI\n');
    lines.push('| Yol | Durum | Tür |');
    lines.push('|-----|-------|-----|');
    for (const r of ev.reachable) lines.push(`| ${r.path} | HTTP ${r.status} | ${r.kind === 'spec' ? 'OpenAPI/Swagger şeması' : r.kind === 'graphql' ? 'GraphQL' : 'Swagger/ReDoc arayüzü'} |`);
    lines.push('');
  } else {
    lines.push('Denenen ~12 yaygın API dokümantasyon yolunda (`/openapi.json`, `/swagger.json`, `/v3/api-docs`, `/swagger-ui.html` vb.) herkese açık bir şema/arayüz bulunamadı.');
    lines.push('');
  }

  if (spec) {
    lines.push('## API ŞEMASI DETAYI\n');
    lines.push(`- Şema yolu: \`${spec.path}\``);
    if (spec.title) lines.push(`- Başlık: ${spec.title}${spec.version ? ` (v${spec.version})` : ''}`);
    lines.push(`- Tanımlı uç nokta sayısı: **${spec.endpointCount}**`);
    lines.push(`- Genel kimlik doğrulama tanımı: ${spec.hasGlobalAuth ? 'var (global `security`)' : '⚠️ şemada global `security` tanımı yok'}`);
    lines.push('');
    if (sensitive.length) {
      lines.push('### Hassas uç noktalar\n');
      lines.push('Yol/işlem adı hassas anahtar kelime içeren uç noktalar (yalnızca şemadan; **çağrılmamıştır**):');
      lines.push('');
      lines.push('| Metot | Yol | Kimlik doğrulama |');
      lines.push('|-------|-----|------------------|');
      for (const s of sensitive.slice(0, 25)) lines.push(`| ${s.method} | ${s.path} | ${s.noAuth ? '⚠️ tanımsız/yok' : 'tanımlı'} |`);
      lines.push('');
      if (noAuthSensitive.length) lines.push(`> **${noAuthSensitive.length} hassas uç nokta** şemada kimlik doğrulama tanımı olmadan listeleniyor. Bu, yetkisiz erişime açık olabileceklerine dair güçlü bir göstergedir (doğrulama için manuel test gerekir).`);
      lines.push('');
    }
  }

  lines.push('> Kapsam: Yalnızca herkese açık dokümantasyon yolları GET ile denenmiştir; hiçbir uç nokta çağrılmamış/istismar edilmemiştir (pasif keşif).');

  const fixText = level === 'low'
    ? '### API & Swagger Keşfi\n\nHerkese açık API dokümantasyonu bulunamadı. Yine de üretimde Swagger/OpenAPI arayüzlerini kapatmayı veya kimlik doğrulama arkasına almayı standart hale getirin.'
    : '### API & Swagger Keşfi — düzeltme\n\n' + [
        '- Üretim ortamında Swagger UI / ReDoc / `*/api-docs` / `openapi.json` gibi şema uçlarını **kapatın** veya kimlik doğrulama (IP allowlist / SSO) arkasına alın.',
        spec && !spec.hasGlobalAuth ? '- API şemanıza global `security` tanımı ekleyin; her hassas uç nokta için kimlik doğrulama/yetki zorunlu olsun.' : '',
        noAuthSensitive.length ? '- Kimlik doğrulaması görünmeyen hassas uç noktaları (admin/user/export/upload vb.) yetkilendirme kontrolünden geçirin; yetkisiz erişimi test edip kapatın.' : '',
        ev.reachable.some((r) => r.kind === 'graphql') ? '- GraphQL introspection’ı üretimde kapatın (`introspection: false`).' : '',
      ].filter(Boolean).join('\n');

  return { title: 'API & Swagger Keşfi', level, headline, body: lines.join('\n'), fixText };
}

// ======================================================================================
// 3) cms_cve
// ======================================================================================
function cveLevel(ev: CmsEvidence): Level {
  if (!ev.cms) return 'low';
  const worst = ev.cves.reduce((m, c) => Math.max(m, c.score), 0);
  const hasCrit = ev.cves.some((c) => c.severity === 'CRITICAL' || c.score >= 9);
  const hasHigh = ev.cves.some((c) => c.severity === 'HIGH' || c.score >= 7);
  const hasMed = ev.cves.some((c) => c.severity === 'MEDIUM' || c.score >= 4);
  if (hasCrit || hasHigh) return 'high';
  if (hasMed || worst > 0) return 'medium-high';
  if (ev.cms && !ev.version) return 'medium'; // CMS var ama surum yok -> guncellik dogrulanamiyor
  return 'low';
}

function buildCmsArea(ev: CmsEvidence): Area {
  const level = cveLevel(ev);
  const critHigh = ev.cves.filter((c) => c.severity === 'CRITICAL' || c.severity === 'HIGH' || c.score >= 7).length;

  const headline = !ev.cms
    ? 'Bilinen bir CMS parmak izi tespit edilmedi'
    : critHigh
      ? `${ev.cms}${ev.version ? ` ${ev.version}` : ''} — ${critHigh} yüksek/kritik CVE ile eşleşiyor`
      : ev.cves.length
        ? `${ev.cms}${ev.version ? ` ${ev.version}` : ''} — ${ev.cveTotal} bilinen CVE ile eşleşiyor`
        : ev.version
          ? `${ev.cms} ${ev.version} tespit edildi; eşleşen CVE bulunamadı`
          : `${ev.cms} tespit edildi; sürüm belirlenemedi`;

  const lines: string[] = [];
  if (!ev.cms) {
    lines.push('Ana sayfa yanıtı (HTTP başlıkları + `<meta generator>` + HTML kalıpları) üzerinden bilinen bir CMS/çatı parmak izi tespit edilmedi. Bu, özel geliştirilmiş bir uygulama veya iyi gizlenmiş bir kurulum olabileceğine işaret eder.');
    lines.push('');
  } else {
    lines.push('## PARMAK İZİ\n');
    lines.push(`- Tespit edilen sistem: **${ev.cms}${ev.version ? ` ${ev.version}` : ''}**`);
    lines.push(`- Nasıl tespit edildi: ${ev.evidence.join('; ')}`);
    if (ev.extras.length) lines.push(`- Ek gözlemler: ${ev.extras.join(' · ')}`);
    if (!ev.version) lines.push('- ⚠️ Sürüm belirlenemedi — CVE eşlemesi için sürüm gereklidir; güncellik dışarıdan doğrulanamadı.');
    lines.push('');

    if (ev.cpeQueried) {
      lines.push('## BİLİNEN CVE EŞLEŞMELERİ (NVD)\n');
      if (!ev.cveOk) {
        lines.push('NVD (NIST Ulusal Zafiyet Veritabanı) sorgusu bu tarama sırasında yanıt vermedi; CVE eşlemesi yapılamadı. Lütfen sürümünüzü NVD üzerinde manuel doğrulayın.');
      } else if (ev.cveTotal === 0) {
        lines.push(`Tespit edilen sürüm (\`${ev.cpeQueried}\`) için NVD’de eşleşen bilinen CVE bulunamadı. Yine de eklenti/tema güncellemelerini ihmal etmeyin.`);
      } else {
        lines.push(`\`${ev.cpeQueried}\` için NVD’de **${ev.cveTotal}** eşleşen CVE bulundu. En yüksek CVSS skoruna göre ilk ${ev.cves.length} tanesi:`);
        lines.push('');
        lines.push('| CVE | Ciddiyet | CVSS | Özet |');
        lines.push('|-----|----------|------|------|');
        for (const c of ev.cves) {
          const sev = c.severity === 'CRITICAL' ? 'Kritik' : c.severity === 'HIGH' ? 'Yüksek' : c.severity === 'MEDIUM' ? 'Orta' : c.severity === 'LOW' ? 'Düşük' : '—';
          lines.push(`| [${c.id}](https://nvd.nist.gov/vuln/detail/${c.id}) | ${sev} | ${c.score || '—'} | ${c.summary.replace(/\|/g, '\\|')} |`);
        }
        lines.push('');
        if (ev.cveTotal > ev.cves.length) lines.push(`_(+${ev.cveTotal - ev.cves.length} eşleşme daha; tam liste NVD’de bu sürümle ilişkilendirilmiştir.)_`);
        lines.push('');
        lines.push(CAUTION_CVE);
      }
      lines.push('');
    }
  }
  lines.push('> Kapsam: Pasif parmak izi + NVD üzerinden bilinen-CVE eşlemesi. Hiçbir CVE **istismar edilmemiş/doğrulanmamıştır**.');

  const fixText = !ev.cms
    ? '### CMS & Bilinen CVE\n\nBilinen bir CMS tespit edilmedi; özel uygulamalar için düzenli bağımlılık taraması (SCA) ve güvenlik güncellemeleri önerilir.'
    : '### CMS & Bilinen CVE — düzeltme\n\n' + [
        `- **${ev.cms}${ev.version ? ` ${ev.version}` : ''}** kurulumunu en güncel kararlı sürüme yükseltin; otomatik güvenlik güncellemelerini açın.`,
        ev.cves.length ? '- Yukarıdaki CVE’leri NVD bağlantılarından inceleyin; güncelleme ile kapananları öncelikli uygulayın, kapanmayanlar için üreticinin azaltıcı önerilerini (WAF kuralı/yapılandırma) uygulayın.' : '',
        '- Kullanılmayan eklenti/tema/modülleri kaldırın; kalanları güncel tutun (CVE’lerin önemli kısmı eklenti/tema kaynaklıdır).',
        '- Sürüm/teknoloji ifşasını azaltın: `<meta generator>`, `X-Powered-By`, `/readme.html`, `/CHANGELOG.txt` gibi sürüm sızdıran noktaları kaldırın/kapatın.',
      ].filter(Boolean).join('\n');

  return { title: 'CMS & Bilinen CVE Taraması', level, headline, body: lines.join('\n'), fixText };
}

// ======================================================================================
// BIRLESTIRME
// ======================================================================================
export function combineReconAreas(ev: ReconEvidence): { findings: string; fixText: string } | null {
  // Ucu de veri toplayamadiysa fallback.
  if (!ev.sub.ok && !ev.api.ok && !ev.cms.ok) return null;

  const areas: Area[] = [buildSubArea(ev.sub), buildApiArea(ev.api), buildCmsArea(ev.cms)];

  const ranked = areas.map((a, i) => ({ a, i })).sort((x, y) => levelRank(y.a.level) - levelRank(x.a.level));
  const baseWorst = ranked[0].a.level;
  const worstArea = ranked[0].a;
  // Birikimli risk (surface ile tutarli): en yuksek 'Orta-Yüksek' iken 2+ alan Orta+ ise -> Yüksek.
  const mediumPlus = areas.filter((a) => levelRank(a.level) >= 1).length;
  const cumulative = baseWorst === 'medium-high' && mediumPlus >= 2;
  const worst: Level = cumulative ? 'high' : baseWorst;

  const summary: string[] = [];
  summary.push(
    worst === 'low'
      ? '- **Genel risk seviyesi: Düşük** — keşif yüzeyiniz 3 alanda incelendi; devralınabilir alt domain, açık hassas API veya bilinen yüksek CVE öne çıkmadı.'
      : cumulative
        ? `- **Genel risk seviyesi: Yüksek** — 3 alan incelendi; birden fazla alan aynı anda risk taşıyor (en yükseği **${worstArea.title}** — ${worstArea.headline}).`
        : `- **Genel risk seviyesi: ${RISK_WORD[worst]}** — 3 alan incelendi; en yüksek risk **${worstArea.title}** alanında (${worstArea.headline}).`,
  );
  for (const a of areas) summary.push(`- **${a.title}:** ${RISK_WORD[a.level]} — ${a.headline}`);
  summary.push('- **Önerilen ilk adım:** En yüksek riskli alandan başlayın; her bulgu için adım adım hazır çözümler "AI Çözüm Önerileri" bölümünde sunulur.');

  const genelSentence =
    cumulative
      ? `Birden fazla keşif alanı aynı anda risk taşıyor (en yükseği **${worstArea.title}** — ${worstArea.headline}); birikimli risk nedeniyle genel değerlendirme Yüksek. Aşağıda her alan ayrı ayrı raporlanmıştır.`
      : worst === 'high'
        ? `En yüksek risk **${worstArea.title}** alanında (${worstArea.headline}) tespit edildi; öncelikli olarak giderilmesi önerilir. Aşağıda her alan ayrı ayrı raporlanmıştır.`
        : worst === 'medium-high'
          ? `Öne çıkan alan **${worstArea.title}** (${worstArea.headline}); tek başına yüksek etkili. Öncelikli olarak giderilmesi önerilir. Aşağıda her alan ayrı ayrı raporlanmıştır.`
          : worst === 'medium'
            ? `Öne çıkan alan **${worstArea.title}** (${worstArea.headline}); kısa vadede giderilmesi önerilir. Aşağıda her alan ayrı ayrı raporlanmıştır.`
            : 'Keşif yüzeyiniz genel olarak sağlam; rapor yalnızca envanter ve küçük iyileştirme fırsatlarını listeler. Aşağıda her alan ayrı ayrı raporlanmıştır.';

  const areaSections = areas.map((a) => `## ${a.title}\n\n**Genel risk seviyesi: ${RISK_WORD[a.level]} — ${a.headline}**\n\n${a.body}\n`).join('\n');

  const findings =
    `## YÖNETİCİ ÖZETİ\n\n${summary.join('\n')}\n\n` +
    `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: ${RISK_WORD[worst]}**\n\n${genelSentence}\n\n` +
    `${areaSections}`;

  const fixText =
    'Bu bölüm, keşif taramanızda tespit edilen tüm eksiklikler için alan alan düzeltme önerileri içerir.\n\n' +
    areas.map((a) => a.fixText.trim()).filter(Boolean).join('\n\n');

  return { findings, fixText };
}

export async function generateBundleReconReport(host: string): Promise<{ findings: string; fixText: string } | null> {
  const ev = await collectReconEvidence(host);
  return combineReconAreas(ev);
}
