/**
 * "İncelenemedi" raporu — hedefe ULAŞILAMADIĞINDA veya kontrollerin TAMAMI/ÇOĞU veri
 * toplayamadığında üretilir. KRİTİK: 0 bulgu, "test edildi temiz" DEĞİL "hiç test edilemedi"
 * demektir; generator null dönerse pdf VARSAYILAN olarak "Düşük Risk"/"Temiz" gösterir (yanlış-temiz).
 * Bunun yerine "Risk Seviyesi: İncelenemedi" içeren açık bir markdown döneriz:
 *   - pdf.assessBasit -> nötr amber "İncelenemedi" rozeti (yeşil-düşük DEĞİL),
 *   - pdf.buildMasterTable/buildDistribution -> "Temiz" YERİNE "İncelenemedi" uyarısı.
 * Tüm paketler (basit/surface/recon/compliance/active/full) aynı işareti kullanır.
 */
export function unscannableReport(host: string, kind = 'kontroller', de = false): { findings: string; fixText: string } {
  if (de) {
    const findings =
      `## MANAGEMENTZUSAMMENFASSUNG\n\n` +
      `- **Gesamtrisikostufe: Nicht prüfbar** — da das Ziel (${host}) nicht erreichbar war, konnten die ${kind} nicht ausgeführt werden; keine Kontrolle konnte echte Daten erheben.\n` +
      `- Dieses Ergebnis bedeutet **NICHT**, dass die Website SICHER ist; es zeigt lediglich, dass die Kontrollen nicht ausgeführt werden konnten.\n` +
      `- **Empfohlener erster Schritt:** Prüfen Sie, ob die Domain online und von außen erreichbar ist, und wiederholen Sie die Prüfung.\n\n` +
      `## GESAMTBEWERTUNG\n\n**Risikostufe: Nicht prüfbar**\n\n` +
      `Zu den Ports 443 (HTTPS) und 80 (HTTP) des Ziels konnte keine Verbindung hergestellt werden (Zeitüberschreitung, Verbindungsablehnung oder Firewall/Zugriffsbeschränkung). Daher konnten die ${kind} nicht ausgeführt werden und keine Kontrolle konnte echte Daten erheben. Dieser Bericht ist **KEIN** „sauberes/sicheres" Ergebnis; sobald der Zugriff möglich ist, sollte erneut geprüft werden.\n\n` +
      `## FESTGESTELLTE RISIKEN\n\n_Da das Ziel nicht erreichbar war, konnten die Kontrollen nicht ausgeführt werden — das Ergebnis ist nicht bewertbar._\n`;
    return { findings, fixText: '' };
  }
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
