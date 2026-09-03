/**
 * (ÜCRETSİZ ANLIK ÖN-TARAMA — lead-gen teaser) SADECE PASİF dış gözlem. Basit Tarama'nın
 * PASİF motorunu (collectEvidence — resolveOrigin + tek GET + TLS) yeniden KULLANIR; hiçbir
 * aktif prob / enjeksiyon / form-POST / login YAPMAZ (kod seviyesinde pasif-only).
 *
 * KANİBALİZASYON ÇİZGİSİ: yalnız SKOR + ≤3 bulgu BAŞLIĞI + üç-durum döner. Bulgu DETAYI,
 * platforma özel DÜZELTME KODLARI, ek pasif kontrol dökümü, indirilebilir PDF → BURADA YOK
 * (bunlar Basit Tarama'nın parası). Veri %100 GERÇEK; uydurma/rastgele bulgu ASLA.
 */
import { collectEvidence } from './basitReport.js';

export type InstantSeverity = 'high' | 'medium' | 'low';
export type InstantFinding = { title: string; severity: InstantSeverity };
export type InstantResult =
  | { status: 'unreachable' }
  | { status: 'access_error'; httpStatus: number }  // bağlantı kuruldu ama 4xx/5xx (engel/erişim kısıtı) → skorlanamaz
  | {
      status: 'ok';
      score: number;               // 0-100 (gerçek pasif bulgulara dayalı)
      grade: 'A' | 'B' | 'C' | 'D' | 'E' | 'F';
      total: number;               // toplam gerçek bulgu sayısı ("+N daha" kilidi için)
      shown: InstantFinding[];     // teaser'da gösterilecek ≤3 başlık (yalnız "ne eksik")
      locked: number;              // total - shown.length (kilitli kalan)
      clean: boolean;              // 0 bulgu → temel katman temiz
      httpsOk: boolean;
    };

// Yalnız VARLIK kontrolü yapılan güvenlik başlıkları (pasif). Etiket = "ne eksik" farkındalığı;
// NASIL düzeltilir (kod/adım) BURADA verilmez.
type L3 = { tr: string; de: string; en: string };
const SEC_HEADERS: Array<{ hdr: string; label: L3; critical: boolean }> = [
  { hdr: 'content-security-policy', label: { tr: 'Content-Security-Policy (CSP) eksik', de: 'Content-Security-Policy (CSP) fehlt', en: 'Content-Security-Policy (CSP) missing' }, critical: true },
  { hdr: 'x-frame-options', label: { tr: 'X-Frame-Options eksik (clickjacking koruması)', de: 'X-Frame-Options fehlt (Clickjacking-Schutz)', en: 'X-Frame-Options missing (clickjacking protection)' }, critical: true },
  { hdr: 'strict-transport-security', label: { tr: 'HSTS (Strict-Transport-Security) eksik', de: 'HSTS (Strict-Transport-Security) fehlt', en: 'HSTS (Strict-Transport-Security) missing' }, critical: false },
  { hdr: 'x-content-type-options', label: { tr: 'X-Content-Type-Options eksik (MIME-sniffing)', de: 'X-Content-Type-Options fehlt (MIME-Sniffing)', en: 'X-Content-Type-Options missing (MIME sniffing)' }, critical: false },
  { hdr: 'referrer-policy', label: { tr: 'Referrer-Policy eksik', de: 'Referrer-Policy fehlt', en: 'Referrer-Policy missing' }, critical: false },
  { hdr: 'permissions-policy', label: { tr: 'Permissions-Policy eksik', de: 'Permissions-Policy fehlt', en: 'Permissions-Policy missing' }, critical: false },
];

export async function runInstantScan(host: string, lang: 'tr' | 'de' | 'en' = 'tr'): Promise<InstantResult> {
  const t = (tr: string, de: string, en: string) => (lang === 'de' ? de : lang === 'en' ? en : tr);
  const ev = await collectEvidence(host);

  // (ÜÇ-DURUM) Ne https(443) ne http ne TLS yanıt verdi → İncelenemedi. ASLA "temiz" deme, sahte sonuç yok.
  if (!ev.reachable && !ev.tls.found) return { status: 'unreachable' };

  // (ERİŞİM-HATASI) Bağlantı KURULDU ama ana sayfa 2xx/3xx yerine 4xx/5xx döndü (401/403: engelleme/erişim
  // kısıtı; 5xx: sunucu hatası). Çıplak hata sayfası (ör. Apache 403 ErrorDocument) HİÇBİR güvenlik başlığı
  // taşımaz → onu skorlamak SAHTE "52/100 · 6 bulgu" üretir. Skor/bulgu ÜRETME; dürüst durum dön.
  if (ev.reachable && ev.ok && typeof ev.status === 'number' && ev.status >= 400) {
    return { status: 'access_error', httpStatus: ev.status };
  }

  const findings: InstantFinding[] = [];
  let score = 100;

  // HTTPS yok (şifresiz iletişim) — tek başına ciddi, gerçek bulgu.
  if (ev.reachable && !ev.httpsWorks) {
    findings.push({ title: t('HTTPS desteklenmiyor (şifresiz iletişim)', 'HTTPS wird nicht unterstützt (unverschlüsselte Kommunikation)', 'HTTPS not supported (unencrypted communication)'), severity: 'high' });
    score -= 40;
  }

  // TLS geçerliliği (yalnız https çalışıyorsa anlamlı).
  if (ev.httpsWorks && ev.tls.found) {
    if (ev.tls.hostnameMatch === false) {
      findings.push({ title: t('TLS sertifikası alan adıyla uyuşmuyor', 'TLS-Zertifikat stimmt nicht mit der Domain überein', 'TLS certificate does not match the domain'), severity: 'high' });
      score -= 30;
    } else if (ev.tls.daysLeft != null && ev.tls.daysLeft < 0) {
      findings.push({ title: t('TLS sertifikasının süresi dolmuş', 'TLS-Zertifikat ist abgelaufen', 'TLS certificate has expired'), severity: 'high' });
      score -= 30;
    } else if (ev.tls.daysLeft != null && ev.tls.daysLeft < 15) {
      findings.push({ title: t(`TLS sertifikası ${ev.tls.daysLeft} gün içinde doluyor`, `TLS-Zertifikat läuft in ${ev.tls.daysLeft} Tagen ab`, `TLS certificate expires in ${ev.tls.daysLeft} days`), severity: 'medium' });
      score -= 10;
    }
  }

  // Güvenlik başlıkları — YALNIZ ana sayfa GET'i başarılıysa (aksi halde "eksik" demek yanıltıcı olur).
  if (ev.ok && ev.reachable) {
    for (const h of SEC_HEADERS) {
      if (!ev.headers.has(h.hdr)) {
        findings.push({ title: t(h.label.tr, h.label.de, h.label.en), severity: h.critical ? 'medium' : 'low' });
        score -= h.critical ? 12 : 6;
      }
    }
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 55 ? 'D' : score >= 40 ? 'E' : 'F';

  const rank: Record<InstantSeverity, number> = { high: 0, medium: 1, low: 2 };
  const sorted = findings.slice().sort((a, b) => rank[a.severity] - rank[b.severity]);
  const shown = sorted.slice(0, 3); // KANİBALİZASYON: teaser en fazla 3 başlık

  return {
    status: 'ok',
    score,
    grade,
    total: findings.length,
    shown,
    locked: Math.max(0, findings.length - shown.length),
    clean: findings.length === 0,
    httpsOk: ev.httpsWorks,
  };
}
