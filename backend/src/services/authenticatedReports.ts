/**
 * (Tam Kapsamlı Pentest — FAZ C) AUTHENTICATED DETERMİNİSTİK RAPOR ÜRETİCİSİ.
 *
 * FAZ B oturumunu (AuthSession) kullanan 6 kontrolü (çerez bayrakları, session fixation, logout,
 * forced browsing + authenticated injection + authenticated IDOR) çalıştırır ve Aktif Doğrulama
 * raporuyla TUTARLI (NE KONTROL EDİLDİ / BULGULAR / Kapsam kutuları) TEK dokümana birleştirir.
 * Tüm Türkçe metin KOD tarafından yazılır (ajan yok).
 */
import { collectInjectionEvidence, collectIdorEvidence } from './activeVerifyEvidence.js';
import {
  collectCookieFlagsEvidence, collectSessionFixationEvidence, collectLogoutEvidence, collectForcedBrowsingEvidence,
} from './authenticatedChecks.js';
import {
  buildActiveCheckReport, buildInjectionReport, buildIdorReport,
  RISK_WORD, levelRank, extractLevel, headlineOf, detailOnly, type Level,
} from './activeVerifyReports.js';
import type { AuthSession } from './authSession.js';

const COOKIE_CFG = {
  title: 'Oturum Çerezi Bayrakları', whatChecked: [
    'Login yanıtındaki `Set-Cookie` başlıkları toplandı (FAZ B oturum yakalama).',
    'Her oturum çerezi için **Secure / HttpOnly / SameSite** güvenlik bayrakları kontrol edildi.',
    'Ağ isteği gönderilmedi — yalnız login yanıtı analiz edildi.',
  ],
  fixTitle: 'Çerez Güvenliği',
  fixFound: ['Oturum çerezlerine **Secure + HttpOnly + SameSite=Strict/Lax** bayraklarını ekleyin.', 'HttpOnly, çerezin JavaScript ile (XSS) okunmasını engeller; Secure, düz HTTP’de sızmasını önler; SameSite CSRF’i azaltır.'],
  fixClean: ['Oturum çerezlerinde Secure/HttpOnly/SameSite bayraklarını proaktif olarak zorunlu kılın.'],
  cleanGenel: 'Oturum çerezlerinde eksik güvenlik bayrağı gözlemlenmedi (veya oturum çerez-tabanlı değil).',
};
const FIXATION_CFG = {
  title: 'Session Fixation', whatChecked: [
    'Login ÖNCESİ (kimlik-doğrulamasız) ana sayfadan alınan oturum çerezi değeri gözlemlendi.',
    'Login SONRASI oturum çerezi değeriyle **karşılaştırıldı** (aynıysa sunucu oturumu yenilemiyor).',
    'Yalnız tek GET; hiçbir state değiştirilmedi.',
  ],
  fixTitle: 'Session Fixation',
  fixFound: ['Başarılı girişte oturum tanımlayıcısını **mutlaka yenileyin** (session regeneration); login öncesi verilen id’yi geçersiz kılın.'],
  fixClean: ['Girişte oturum id yenilemeyi (session regeneration) standart hale getirin.'],
  cleanGenel: 'Login sonrası oturum çerezi yenilendiği (veya oturum çerez-tabanlı olmadığı) için fixation göstergesi gözlemlenmedi.',
};
const LOGOUT_CFG = {
  title: 'Logout / Oturum Geçersizleştirme', whatChecked: [
    'Oturumla 200 dönen korumalı bir uç (whoami/profil) tespit edildi.',
    'GET ile çağrılabilen bir logout uç noktası denendi (**POST yok** — state değişmez).',
    'Logout SONRASI AYNI token ile korumalı uca tekrar erişilebiliyor mu kontrol edildi.',
  ],
  fixTitle: 'Oturum Geçersizleştirme',
  fixFound: ['Logout’ta oturum token’ını **sunucu tarafında geçersiz kılın** (revocation/expiry); istemci-tarafı token silme tek başına yeterli değildir.'],
  fixClean: ['Sunucu-taraflı oturum geçersizleştirme (revocation) uygulayın.'],
  cleanGenel: 'Logout sonrası oturum geçersizleştirildiği (veya sunucu-taraflı logout uç noktası olmadığı) için bulgu gözlemlenmedi.',
};
const FORCED_CFG = {
  title: 'Forced Browsing / Fonksiyon-Seviye Yetki', whatChecked: [
    'Yaygın admin/yönetim uç noktalarına ELDEKİ (muhtemelen düşük yetkili) test hesabının oturumuyla **GET** isteği atıldı.',
    'Yanlış-pozitifi önlemek için yalnız ana-sayfa shell’inden **FARKLI** içerik/JSON dönen 200’ler bulgu sayıldı.',
    'Tek deneme, GET-only, devre kesiciye tabi.',
  ],
  fixTitle: 'Fonksiyon-Seviye Yetkilendirme',
  fixFound: ['Her yönetim/hassas uç noktasında **sunucu-taraflı rol/yetki kontrolü** uygulayın; yalnız UI’da gizlemek yeterli değildir.'],
  fixClean: ['Yönetim uç noktalarını sunucu-taraflı rol kontrolüyle koruyun (proaktif).'],
  cleanGenel: 'Düşük yetkili oturumla erişilebilen bir admin/yönetim uç noktası gözlemlenmedi.',
};

type Run = { title: string; conf: 'Yüksek' | 'Orta' | 'Düşük'; rep: { findings: string; fixText: string } | null; inputs: number; probes: number; fc: number };

/** 6 authenticated kontrolü çalıştır + TEK rapora birleştir. Hedefe ulaşılamazsa null. */
export async function generateAuthenticatedReport(host: string, session: AuthSession): Promise<{ findings: string; fixText: string } | null> {
  const runs: Run[] = [];
  const cookieEv = collectCookieFlagsEvidence(session);
  runs.push({ title: 'Oturum Çerezi Bayrakları', conf: 'Yüksek', rep: buildActiveCheckReport(cookieEv, COOKIE_CFG), inputs: cookieEv.inputsFound, probes: cookieEv.probesSent, fc: cookieEv.findings.length });
  const fixEv = await collectSessionFixationEvidence(host, session).catch(() => null);
  runs.push({ title: 'Session Fixation', conf: 'Orta', rep: fixEv ? buildActiveCheckReport(fixEv, FIXATION_CFG) : null, inputs: fixEv?.inputsFound ?? 0, probes: fixEv?.probesSent ?? 0, fc: fixEv?.findings.length ?? 0 });
  const logoutEv = await collectLogoutEvidence(host, session).catch(() => null);
  runs.push({ title: 'Logout / Oturum Geçersizleştirme', conf: 'Orta', rep: logoutEv ? buildActiveCheckReport(logoutEv, LOGOUT_CFG) : null, inputs: logoutEv?.inputsFound ?? 0, probes: logoutEv?.probesSent ?? 0, fc: logoutEv?.findings.length ?? 0 });
  const forcedEv = await collectForcedBrowsingEvidence(host, session).catch(() => null);
  runs.push({ title: 'Forced Browsing / Fonksiyon-Seviye Yetki', conf: 'Orta', rep: forcedEv ? buildActiveCheckReport(forcedEv, FORCED_CFG) : null, inputs: forcedEv?.inputsFound ?? 0, probes: forcedEv?.probesSent ?? 0, fc: forcedEv?.findings.length ?? 0 });
  const injEv = await collectInjectionEvidence(host, session).catch(() => null);
  runs.push({ title: 'Authenticated Enjeksiyon (SQLi/XSS)', conf: 'Yüksek', rep: injEv ? buildInjectionReport(injEv) : null, inputs: injEv?.inputsFound ?? 0, probes: injEv?.probesSent ?? 0, fc: injEv?.findings.length ?? 0 });
  const idorEv = await collectIdorEvidence(host, session).catch(() => null);
  runs.push({ title: 'Authenticated IDOR (kendi kaynakları)', conf: 'Orta', rep: idorEv ? buildIdorReport(idorEv) : null, inputs: idorEv?.candidates ?? 0, probes: idorEv?.probesSent ?? 0, fc: idorEv?.findings.length ?? 0 });

  if (runs.every((r) => !r.rep)) return null;

  const levels: Array<Level | null> = runs.map((r) => (r.rep ? extractLevel(r.rep.findings) : null));
  const ranked = levels.map((lv, i) => ({ lv, i })).filter((x): x is { lv: Level; i: number } => x.lv !== null).sort((a, b) => levelRank(b.lv) - levelRank(a.lv));
  const worst: Level = ranked.length ? ranked[0].lv : 'low';
  const worstTitle = ranked.length ? runs[ranked[0].i].title : '';
  const anyFinding = runs.some((r) => r.fc > 0);
  const totalProbes = runs.reduce((s, r) => s + r.probes, 0);
  const dataOk = runs.filter((r) => r.rep).length;

  const box =
    `> ### Değerlendirme Özeti (Authenticated)\n` +
    `> **Bu tarama, verilen TEST hesabının oturumuyla KİMLİK-DOĞRULAMALI (login’li) bağlamda yapılmıştır.** ` +
    `${runs.length} authenticated kontrol değerlendirildi; toplam **${totalProbes}** istek. ` +
    (anyFinding ? `En yüksek risk **${worstTitle}** alanında (aşağıda detaylı).` : `Doğrulanmış kritik/yüksek seviyeli bir zafiyet öne çıkmadı.`) +
    `\n>\n> _Şifre hiçbir aşamada ajana/PentAGI’ye gönderilmedi; backend deterministik login yapıp yalnız oturumu (cookie/token) kullandı._`;

  const statusOf = (r: Run, lv: Level | null): string => {
    if (!r.rep) return 'Veri toplanamadı';
    if (r.fc > 0 && lv === 'high') return '⚠ Zafiyet göstergesi';
    if (r.fc > 0) return '⚠ Sınırlı gösterge';
    if (r.inputs === 0) return 'Uygulanabilir değil (Kapsam dışı)';
    return '✓ Zafiyet kanıtı yok';
  };
  const confCell = (r: Run): string => (r.rep && r.inputs > 0 ? r.conf : 'Kapsam dışı');
  const tableRows = runs.map((r, i) => `| ${r.title} | ${statusOf(r, levels[i])} | ${confCell(r)} |`).join('\n');
  const controlTable = `## KONTROL ÖZETİ\n\n| Kontrol | Sonuç | Güven |\n|---------|-------|-------|\n${tableRows}\n\n> Güven yalnızca gerçekten uygulanabilen (giriş/çerez/uç bulunan) kontroller için gösterilir; uygulanamayan kontroller **Kapsam dışı**dır (ör. çerez yerine token kullanan oturumda çerez-bayrağı/fixation).\n`;

  const summary: string[] = [];
  summary.push(
    worst === 'low'
      ? `- **Genel risk seviyesi: Düşük** — ${runs.length} authenticated kontrol değerlendirildi; doğrulanmış kritik/yüksek seviyeli bir zafiyet öne çıkmadı.`
      : `- **Genel risk seviyesi: ${RISK_WORD[worst]}** — en yüksek risk **${worstTitle}** alanında.`,
  );
  summary.push(
    `- **Kapsam:** Bu bölüm **kimlik-doğrulamalı (login’li)** bağlamda çalışır; login sonrası ortaya çıkan çerez/oturum/yetki ve authenticated enjeksiyon/IDOR sınıflarını kapsar. Yetki yükseltme, çok-adımlı iş mantığı ve cross-account (başka kullanıcının verisi) IDOR bu bölümün kapsamı dışındadır.`,
  );
  runs.forEach((r, i) => {
    const lv = levels[i];
    if (!r.rep || !lv) { summary.push(`- **${r.title}:** veri toplanamadı.`); return; }
    const hl = headlineOf(r.rep.findings);
    summary.push(`- **${r.title}:** ${RISK_WORD[lv]}${hl ? ` — ${hl}` : ''}`);
  });
  summary.push('- **Önerilen ilk adım:** Çalıştırılan kontrollerdeki bulguları giderin; hazır adımlar "AI Çözüm Önerileri" bölümünde.');

  const genel =
    (worst === 'low'
      ? `${runs.length} authenticated doğrulama kontrolü değerlendirildi; doğrulanmış kritik/yüksek seviyeli bir zafiyet öne çıkmadı.`
      : `Çalıştırılan authenticated kontrollerde en yüksek risk **${worstTitle}** alanında tespit edildi; öncelikli olarak giderilmesi/doğrulanması önerilir.`) +
    ` Tüm kontroller GET-only/gözlemseldir; state-değiştiren istek gönderilmemiştir. Şifre ajana/PentAGI’ye gönderilmemiş, backend login yapıp yalnız oturumu kullanmıştır.`;

  const sections = runs.map((r) => {
    if (!r.rep) return `## ${r.title}\n\n> Bu kontrol için veri toplanamadı.\n`;
    return `## ${r.title}\n\n${detailOnly(r.rep.findings)}\n`;
  }).join('\n');

  const findings =
    `${box}\n\n` +
    `## YÖNETİCİ ÖZETİ\n\n${summary.join('\n')}\n\n` +
    `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: ${RISK_WORD[worst]}**\n\n${genel}\n\n` +
    `${controlTable}\n${sections}`;

  const fixParts = runs.map((r) => (r.rep && r.rep.fixText.trim() ? `### ${r.title}\n\n${r.rep.fixText.trim()}` : '')).filter(Boolean);
  const fixText = `Bu bölüm, çalıştırılan authenticated kontrollerde tespit edilen bulgular için düzeltme önerileri içerir.\n\n${fixParts.join('\n\n')}`;

  void dataOk;
  return { findings, fixText };
}
