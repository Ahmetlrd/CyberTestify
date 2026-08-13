/**
 * "İncelenemedi" raporu — hedefe ULAŞILAMADIĞINDA veya kontrollerin TAMAMI/ÇOĞU veri
 * toplayamadığında üretilir. KRİTİK: 0 bulgu, "test edildi temiz" DEĞİL "hiç test edilemedi"
 * demektir; generator null dönerse pdf VARSAYILAN olarak "Düşük Risk"/"Temiz" gösterir (yanlış-temiz).
 * Bunun yerine "Risk Seviyesi: İncelenemedi" içeren açık bir markdown döneriz:
 *   - pdf.assessBasit -> nötr amber "İncelenemedi" rozeti (yeşil-düşük DEĞİL),
 *   - pdf.buildMasterTable/buildDistribution -> "Temiz" YERİNE "İncelenemedi" uyarısı.
 * Tüm paketler (basit/surface/recon/compliance/active/full) aynı işareti kullanır.
 */
export function unscannableReport(host: string, kind = 'kontroller'): { findings: string; fixText: string } {
  const findings =
    `## YÖNETİCİ ÖZETİ\n\n` +
    `- **Genel risk seviyesi: İncelenemedi** — hedefe (${host}) ulaşılamadığı için ${kind} çalıştırılamadı; hiçbir kontrol gerçek veri toplayamadı.\n` +
    `- Bu sonuç sitenin GÜVENLİ olduğu anlamına **GELMEZ**; yalnızca kontrollerin çalıştırılamadığını gösterir.\n` +
    `- **Önerilen ilk adım:** Alan adının yayında ve dışarıdan erişilebilir olduğunu doğrulayıp taramayı tekrarlayın.\n\n` +
    `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: İncelenemedi**\n\n` +
    `Hedefin 443 (HTTPS) ve 80 (HTTP) portlarına bağlantı kurulamadı (zaman aşımı, bağlantı reddi veya güvenlik duvarı/erişim kısıtı). Bu nedenle ${kind} çalıştırılamadı ve hiçbir kontrol gerçek veri toplayamadı. Bu rapor bir "temiz/güvenli" sonucu **DEĞİLDİR**; erişim sağlanınca yeniden taranmalıdır.\n\n` +
    `## TESPİT EDİLEN RİSKLER\n\n_Hedefe ulaşılamadığı için kontroller çalıştırılamadı — sonuç değerlendirilemez._\n`;
  return { findings, fixText: '' };
}
