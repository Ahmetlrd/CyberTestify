import { prisma } from '../db.js';
import { config } from '../config.js';
import { getBundle } from './bundles.js';
import { requiresTestCredentials } from './scanPackages.js';

// Aktif Doğrulama Paketi üye kontrol anahtarları — sipariş e-postasında kapsam netliği için.
const ACTIVE_VERIFY_KEYS = new Set(getBundle('bundle_active_verify')?.memberKeys ?? []);

/**
 * Transactional e-posta (Brevo REST API — POST /v3/smtp/email).
 *
 * Tasarim: BREVO_API_KEY yoksa mailer NO-OP'tur (uyari loglar, false doner) ve HICBIR
 * akisi (odeme/tarama/rapor) BOZMAZ. Tum yuksek-seviye gonderici fonksiyonlari kendi
 * icinde try/catch'lidir; e-posta hatasi asla cagirani patlatmaz.
 *
 * SDK YOK — fetch ile REST; ek bagimlilik gerekmez, Node 18+ global fetch.
 */

const BREVO_URL = 'https://api.brevo.com/v3/smtp/email';

/** Ham gonderim. Basarili ise true. Asla throw etmez. */
export async function sendMail(to: string, subject: string, html: string): Promise<boolean> {
  if (!config.brevo.apiKey) {
    console.warn(`[mail] BREVO_API_KEY yok — e-posta atlandi (to=${to}, konu="${subject}").`);
    return false;
  }
  try {
    const resp = await fetch(BREVO_URL, {
      method: 'POST',
      headers: {
        'api-key': config.brevo.apiKey,
        'content-type': 'application/json',
        accept: 'application/json',
      },
      body: JSON.stringify({
        sender: { email: config.brevo.senderEmail, name: config.brevo.senderName },
        to: [{ email: to }],
        subject,
        htmlContent: html,
      }),
    });
    if (!resp.ok) {
      const body = await resp.text().catch(() => '');
      console.error(`[mail] Brevo hata (${resp.status}) to=${to} konu="${subject}": ${body.slice(0, 300)}`);
      return false;
    }
    console.log(`[mail] gonderildi to=${to} konu="${subject}"`);
    return true;
  } catch (err) {
    console.error(`[mail] gonderim istisnasi to=${to} konu="${subject}":`, err);
    return false;
  }
}

// --- Markali HTML sablon sarmalayici -----------------------------------------
// (Çok-bölge) locale'e göre para formatı: de → de-DE (1.234,56 €), diğer → tr-TR.
function fmtMoney(minor: number, currency: string, locale: 'tr' | 'de' = 'tr'): string {
  const v = (minor / 100).toLocaleString(locale === 'de' ? 'de-DE' : 'tr-TR', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  return `${v} ${currency === 'TRY' ? 'TL' : currency}`;
}
// (Çok-bölge) order.locale → mail dili (tr | de). us/ae ('en') → tr'ye düşer (mevcut davranış; e-posta
// zaten TR'ydi). de siparişlerinde tüm müşteri e-postaları Almanca gönderilir.
function mailLang(orderLocale: string | null | undefined): 'tr' | 'de' {
  return orderLocale === 'de' ? 'de' : 'tr';
}
function esc(s: string): string {
  return String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] as string));
}

/** Ortak marka cercevesi (inline stil — e-posta istemcileri uyumlu). */
function layout(opts: { heading: string; bodyHtml: string; cta?: { label: string; url: string }; lang?: 'tr' | 'de' }): string {
  const lang = opts.lang === 'de' ? 'de' : 'tr';
  const footer = lang === 'de'
    ? `Diese E-Mail wurde automatisch von CyberTestify gesendet. Bei Fragen: <a href="mailto:support@cybertestify.com" style="color:#1C6B60">support@cybertestify.com</a>.<br>CyberTestify — Dienst zur Sicherheits-Vorabbewertung.`
    : `Bu e-posta CyberTestify tarafından otomatik gönderilmiştir. Sorularınız için <a href="mailto:destek@cybertestify.com" style="color:#1C6B60">destek@cybertestify.com</a>.<br>CyberTestify — dijital güvenlik ön-değerlendirme hizmeti.`;
  const cta = opts.cta
    ? `<tr><td style="padding:8px 0 4px"><a href="${esc(opts.cta.url)}" style="display:inline-block;background:#F5A623;color:#123F3A;font-weight:700;text-decoration:none;padding:12px 22px;border-radius:999px;font-size:15px">${esc(opts.cta.label)}</a></td></tr>`
    : '';
  return `<!doctype html><html lang="${lang}"><body style="margin:0;background:#f4f6f5;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1c2b28">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f5;padding:24px 12px">
   <tr><td align="center">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border:1px solid #e3e8e6;border-radius:14px;overflow:hidden">
     <tr><td style="background:#123F3A;padding:18px 24px">
       <span style="color:#ffffff;font-size:18px;font-weight:800;letter-spacing:-.3px">Cyber<span style="color:#F5A623">Testify</span></span>
     </td></tr>
     <tr><td style="padding:26px 24px 8px">
       <h1 style="margin:0 0 12px;font-size:19px;color:#123F3A">${esc(opts.heading)}</h1>
       <div style="font-size:14px;line-height:1.6;color:#3a4a47">${opts.bodyHtml}</div>
     </td></tr>
     <tr><td style="padding:6px 24px 24px"><table role="presentation" cellpadding="0" cellspacing="0">${cta}</table></td></tr>
     <tr><td style="padding:16px 24px;background:#f8faf9;border-top:1px solid #e3e8e6">
       <p style="margin:0;font-size:11px;color:#8a9794;line-height:1.5">${footer}</p>
     </td></tr>
    </table>
   </td></tr>
  </table>
 </body></html>`;
}

async function orderWithRelations(orderId: string) {
  return prisma.order.findUnique({
    where: { id: orderId },
    // include yalnız İLİŞKİLERİ ekler; order scalar 'locale' zaten döner → e-posta dili order.locale'den.
    include: { customer: { select: { email: true, fullName: true } }, package: { select: { displayName: true } }, domain: { select: { hostname: true } } },
  });
}

// --- (0) E-posta dogrulama kodu (kayit sonrasi) -------------------------------
export async function sendEmailVerification(email: string, code: string, lang: 'tr' | 'de' = 'tr'): Promise<boolean> {
  const de = lang === 'de';
  const html = layout({
    lang,
    heading: de ? 'Bestätigen Sie Ihre E-Mail-Adresse' : 'E-posta adresinizi doğrulayın',
    bodyHtml: de
      ? `<p>Willkommen bei CyberTestify. Geben Sie den folgenden Bestätigungscode ein, um Ihr Konto zu aktivieren und Käufe zu tätigen:</p>
      <p style="margin:16px 0;padding:16px;background:#f2f7f5;border:1px dashed #1C6B60;border-radius:10px;text-align:center">
        <span style="font-family:ui-monospace,Menlo,Consolas,monospace;font-size:30px;font-weight:800;letter-spacing:6px;color:#123F3A">${esc(code)}</span>
      </p>
      <p style="color:#8a9794;font-size:13px">Der Code ist <strong>15 Minuten</strong> gültig. Falls Sie dies nicht angefordert haben, können Sie diese E-Mail ignorieren.</p>`
      : `<p>CyberTestify'a hoş geldiniz. Hesabınızı etkinleştirmek ve satın alma yapabilmek için aşağıdaki doğrulama kodunu girin:</p>
      <p style="margin:16px 0;padding:16px;background:#f2f7f5;border:1px dashed #1C6B60;border-radius:10px;text-align:center">
        <span style="font-family:ui-monospace,Menlo,Consolas,monospace;font-size:30px;font-weight:800;letter-spacing:6px;color:#123F3A">${esc(code)}</span>
      </p>
      <p style="color:#8a9794;font-size:13px">Kod <strong>15 dakika</strong> geçerlidir. Bu talebi siz yapmadıysanız bu e-postayı yok sayabilirsiniz.</p>`,
  });
  return sendMail(email, de ? 'Ihr Bestätigungscode — CyberTestify' : 'Doğrulama kodunuz — CyberTestify', html);
}

// --- (A) Sifre sifirlama ------------------------------------------------------
export async function sendPasswordReset(email: string, resetUrl: string, lang: 'tr' | 'de' = 'tr'): Promise<boolean> {
  const de = lang === 'de';
  const html = layout({
    lang,
    heading: de ? 'Passwort zurücksetzen' : 'Şifre sıfırlama talebi',
    bodyHtml: de
      ? `<p>Für Ihr Konto wurde das Zurücksetzen des Passworts angefordert. Klicken Sie auf die Schaltfläche unten, um ein neues Passwort festzulegen.</p>
      <p style="color:#8a9794;font-size:13px">Dieser Link ist <strong>1 Stunde</strong> gültig und kann nur einmal verwendet werden. Falls Sie dies nicht angefordert haben, können Sie diese E-Mail ignorieren; Ihr Passwort bleibt unverändert.</p>`
      : `<p>Hesabınız için şifre sıfırlama talebinde bulunuldu. Yeni şifrenizi belirlemek için aşağıdaki butona tıklayın.</p>
      <p style="color:#8a9794;font-size:13px">Bu bağlantı <strong>1 saat</strong> geçerlidir ve yalnızca bir kez kullanılabilir. Bu talebi siz yapmadıysanız bu e-postayı yok sayabilirsiniz; şifreniz değişmez.</p>`,
    cta: { label: de ? 'Passwort zurücksetzen' : 'Şifremi sıfırla', url: resetUrl },
  });
  return sendMail(email, de ? 'Passwort zurücksetzen — CyberTestify' : 'Şifre sıfırlama — CyberTestify', html);
}

// --- (B) Siparis/odeme onayi (TEK e-posta; bundle icin tum uyeler birlikte) ---
export async function sendOrderConfirmation(orderIds: string[]): Promise<boolean> {
  try {
    const ids = [...new Set(orderIds)].filter(Boolean);
    if (!ids.length) return false;
    const orders = await prisma.order.findMany({
      where: { id: { in: ids } },
      include: { customer: { select: { email: true } }, package: { select: { displayName: true, key: true } }, domain: { select: { hostname: true } } },
    });
    if (!orders.length) return false;
    const email = orders[0].customer.email;
    const hostname = orders[0].domain.hostname;
    const currency = orders[0].currency;
    const lang = mailLang(orders[0].locale);
    const de = lang === 'de';
    const totalMinor = orders.reduce((s, o) => s + o.amountMinorUnit, 0);
    const isBundle = orders.length > 1;
    const items = orders.map((o) => `<li style="margin:2px 0">${esc(o.package.displayName)}</li>`).join('');
    const orderRef = orders.map((o) => o.id.slice(0, 8)).join(', ');
    // Aktif Doğrulama Paketi ise: satın alma ANINDA yazılı kapsam netliği (login’siz yüzey).
    const isActiveVerify = orders.some((o) => ACTIVE_VERIFY_KEYS.has(o.package.key));
    const scopeNote = !isActiveVerify ? '' : de
      ? `<p style="margin:12px 0;padding:10px 14px;background:#f3f7f6;border-left:3px solid #123F3A;border-radius:6px;color:#3a4a47;font-size:13px"><strong>Umfang:</strong> Dieses Paket arbeitet auf der Oberfläche, die keine Authentifizierung erfordert (ohne Login testbar). Tiefe Autorisierungs-/Geschäftslogik-Schwachstellen, die erst nach dem Login auftreten, sind außerhalb des Scope; die Ergebnisse hängen von der Struktur des Ziels ab.</p>`
      : `<p style="margin:12px 0;padding:10px 14px;background:#f3f7f6;border-left:3px solid #123F3A;border-radius:6px;color:#3a4a47;font-size:13px"><strong>Kapsam:</strong> Bu paket kimlik doğrulaması gerektirmeyen (login olmadan test edilebilen) yüzeyde çalışır. Login sonrası ortaya çıkan derin yetkilendirme/iş mantığı zafiyetleri bu paketin kapsamı dışındadır; sonuçlar hedefin yapısına göre değişir.</p>`;
    // (Tam Kapsamlı Pentest — FAZ A) Kimlik-doğrulamalı paket: satın alma anında yazılı "test hesabı" uyarısı.
    const isAuthenticated = orders.some((o) => requiresTestCredentials(o.package.key));
    const credWarn = !isAuthenticated ? '' : de
      ? `<p style="margin:12px 0;padding:10px 14px;background:#fff5f5;border-left:3px solid #c0392b;border-radius:6px;color:#7a2018;font-size:13px"><strong>⚠️ Testkonto:</strong> Dieses Paket umfasst authentifizierte (angemeldete) Tests. Verwenden Sie bitte NICHT Ihr Produktiv-/Hauptkonto, sondern ein TEST-Konto mit minimalen Rechten, Einmalgebrauch und ohne 2FA, und ändern Sie dessen Passwort nach dem Scan. Ihre Zugangsdaten werden verschlüsselt gespeichert und nach dem Scan gelöscht.</p>`
      : `<p style="margin:12px 0;padding:10px 14px;background:#fff5f5;border-left:3px solid #c0392b;border-radius:6px;color:#7a2018;font-size:13px"><strong>⚠️ Test hesabı:</strong> Bu paket kimlik-doğrulamalı (login’li) test içerir. Lütfen üretim/ana hesabınızı DEĞİL; sınırlı yetkili, tek-kullanımlık, 2FA’sı olmayan bir TEST hesabı kullanın ve şifresini tarama sonrası değiştirin. Kimlik bilgileriniz şifreli saklanır ve tarama sonrası silinir.</p>`;
    // (İŞ 4/5) full_pentest artık ödeme sonrası DİREKT başlar. Alıcıya dürüst kapsam/beklenti notu.
    const isFullPentest = orders.some((o) => o.package.key === 'bundle_full_pentest');
    const reviewNote = !isFullPentest ? '' : de
      ? `<p style="margin:12px 0;padding:10px 14px;background:#f3f7f6;border-left:3px solid #123F3A;border-radius:6px;color:#3a4a47;font-size:13px"><strong>Umfang & Erwartung:</strong> Dieses Paket nutzt deterministische authentifizierte Prüfungen + bei zwei Prüfungen eine <strong>KI-gestützte Analyse</strong> (ein einzelner LLM-Beratungsaufruf; kein autonomer/unbegrenzter Pentest). Cross-Account-IDOR (Zugriff auf Daten eines anderen Nutzers) ist außerhalb des Scope. Die KI-gestützte Analyse findet bei manchen Zielen möglicherweise keinen anwendbaren Indikator; dann bleiben die Ergebnisse auf die deterministischen authentifizierten Prüfungen beschränkt — das ist normal und der Bericht zeigt es transparent.</p>`
      : `<p style="margin:12px 0;padding:10px 14px;background:#f3f7f6;border-left:3px solid #123F3A;border-radius:6px;color:#3a4a47;font-size:13px"><strong>Kapsam & beklenti:</strong> Bu paket deterministik kimlik-doğrulamalı kontroller + iki kontrolde <strong>yapay zekâ destekli analiz</strong> kullanır (tek LLM danışma çağrısı; otonom/sınırsız pentest değildir). Cross-account (başka bir kullanıcının verisine erişim) IDOR bu sürümün kapsamı dışındadır. Yapay zekâ destekli analiz katmanı bazı hedeflerde uygulanabilir bir gösterge bulamayabilir; bu durumda sonuçlar deterministik authenticated kontrollerle sınırlı kalır — bu normaldir ve rapor bunu şeffaf gösterir.</p>`;
    const tRow = (label: string) => `<td style="padding:12px 14px;border-bottom:1px solid #eef2f1;font-size:13px;color:#8a9794">${label}</td>`;
    const body = de
      ? `<p>Ihre Bestellung ist eingegangen und Ihre Zahlung wurde bestätigt. Vielen Dank.</p>
      <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;margin:12px 0;border:1px solid #e3e8e6;border-radius:10px">
        <tr>${tRow('Ziel')}<td style="padding:12px 14px;border-bottom:1px solid #eef2f1;font-size:14px;font-weight:600;text-align:right">${esc(hostname)}</td></tr>
        <tr><td style="padding:12px 14px;border-bottom:1px solid #eef2f1;font-size:13px;color:#8a9794;vertical-align:top">${isBundle ? 'Paketinhalt' : 'Paket'}</td><td style="padding:12px 14px;border-bottom:1px solid #eef2f1;font-size:14px;font-weight:600;text-align:right"><ul style="margin:0;padding:0;list-style:none">${items}</ul></td></tr>
        <tr>${tRow('Bestellnummer')}<td style="padding:12px 14px;border-bottom:1px solid #eef2f1;font-size:13px;text-align:right">${esc(orderRef)}</td></tr>
        <tr><td style="padding:12px 14px;font-size:13px;color:#8a9794">Betrag</td><td style="padding:12px 14px;font-size:16px;font-weight:800;color:#123F3A;text-align:right">${fmtMoney(totalMinor, currency, 'de')}</td></tr>
      </table>
      ${reviewNote}${credWarn}${scopeNote}<p style="color:#3a4a47">Ihr Scan wurde eingereiht. <strong>Wenn er beginnt</strong>, senden wir Ihnen eine weitere E-Mail; Sie können den Status auch in Ihrem Panel verfolgen.</p>`
      : `<p>Siparişiniz alındı ve ödemeniz onaylandı. Teşekkür ederiz.</p>
      <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;margin:12px 0;border:1px solid #e3e8e6;border-radius:10px">
        <tr>${tRow('Hedef')}<td style="padding:12px 14px;border-bottom:1px solid #eef2f1;font-size:14px;font-weight:600;text-align:right">${esc(hostname)}</td></tr>
        <tr><td style="padding:12px 14px;border-bottom:1px solid #eef2f1;font-size:13px;color:#8a9794;vertical-align:top">${isBundle ? 'Paket içeriği' : 'Paket'}</td><td style="padding:12px 14px;border-bottom:1px solid #eef2f1;font-size:14px;font-weight:600;text-align:right"><ul style="margin:0;padding:0;list-style:none">${items}</ul></td></tr>
        <tr>${tRow('Sipariş no')}<td style="padding:12px 14px;border-bottom:1px solid #eef2f1;font-size:13px;text-align:right">${esc(orderRef)}</td></tr>
        <tr><td style="padding:12px 14px;font-size:13px;color:#8a9794">Tutar</td><td style="padding:12px 14px;font-size:16px;font-weight:800;color:#123F3A;text-align:right">${fmtMoney(totalMinor, currency)}</td></tr>
      </table>
      ${reviewNote}${credWarn}${scopeNote}<p style="color:#3a4a47">Taramanız sıraya alındı. <strong>Başladığında</strong> size ayrıca bir e-posta göndereceğiz; durumu panelinizden de takip edebilirsiniz.</p>`;
    const html = layout({ lang, heading: de ? 'Ihre Bestellung ist eingegangen' : 'Siparişiniz alındı', bodyHtml: body, cta: { label: de ? 'Bestellung ansehen' : 'Siparişimi görüntüle', url: `${config.frontendUrl}/dashboard/${orders[0].id}` } });
    return await sendMail(email, de ? 'Ihre Bestellung ist eingegangen — CyberTestify' : 'Siparişiniz alındı — CyberTestify', html);
  } catch (err) {
    console.error('[mail] sendOrderConfirmation hata:', err);
    return false;
  }
}

// --- (Tam Kapsamlı Pentest — FAZ B) Login başarısız bildirimi (kredi YOK — İŞ 2) ------
export async function sendAuthLoginFailed(orderId: string, twoFactor: boolean, reason?: string): Promise<boolean> {
  try {
    const o = await prisma.order.findUnique({
      where: { id: orderId },
      include: { customer: { select: { email: true } }, domain: { select: { hostname: true } } },
    });
    if (!o) return false;
    const lang = mailLang(o.locale);
    const de = lang === 'de';
    // target_unreachable = HEDEF O AN erişilemez döndü; giriş HİÇ denenmedi (mesaj gerçek nedeni söyler).
    if (reason === 'target_unreachable') {
      const body = de
        ? `<p>Während Ihres Scans war <strong>${esc(o.domain.hostname)}</strong> <strong>nicht erreichbar</strong> (der Server lieferte einen Fehler-/Nicht-erreichbar-Status) — dies ist KEIN Problem mit Benutzername/Passwort; es wurde nicht einmal ein Login-Versuch unternommen.</p>
        <p>Bitte stellen Sie sicher, dass Ihre Website derzeit <strong>online und erreichbar</strong> ist, und starten Sie den Scan erneut. Ihre Testkonto-Daten sind weiterhin gespeichert — Sie müssen sie nicht erneut eingeben.</p>
        <p style="margin-top:12px;padding:10px 14px;background:#f3f7f6;border-left:3px solid #123F3A;border-radius:6px;color:#3a4a47;font-size:13px">
          Falls das Problem bestehen bleibt oder Sie eine Erstattung wünschen, kontaktieren Sie uns unter <a href="mailto:support@cybertestify.com" style="color:#123F3A;font-weight:600">support@cybertestify.com</a> — wir prüfen Ihr Anliegen persönlich und helfen weiter.
        </p>`
        : `<p>Taramanız sırasında <strong>${esc(o.domain.hostname)}</strong> adresine <strong>erişilemedi</strong> (sunucu hata/erişilemez durum döndürdü) — bu, kullanıcı adı/şifre ile ilgili bir sorun DEĞİLDİR; giriş denemesi bile yapılmadı.</p>
        <p>Lütfen sitenizin şu an <strong>yayında ve erişilebilir</strong> olduğundan emin olup taramayı tekrar deneyin. Verdiğiniz test hesabı bilgileri hâlâ kayıtlı — tekrar girmenize gerek yok.</p>
        <p style="margin-top:12px;padding:10px 14px;background:#f3f7f6;border-left:3px solid #123F3A;border-radius:6px;color:#3a4a47;font-size:13px">
          Sorun devam ederse ya da iade isterseniz <a href="mailto:support@cybertestify.com" style="color:#123F3A;font-weight:600">support@cybertestify.com</a> adresinden bize ulaşın — talebinizi elden inceleyip yardımcı olalım.
        </p>`;
      const html = layout({ lang, heading: de ? 'Ihr Ziel war nicht erreichbar' : 'Hedefinize erişilemedi', bodyHtml: body, cta: { label: de ? 'Bestellung ansehen' : 'Siparişimi görüntüle', url: `${config.frontendUrl}/dashboard/${o.id}` } });
      return await sendMail(o.customer.email, de ? 'Scan nicht abgeschlossen — Ziel nicht erreichbar' : 'Tarama tamamlanamadı — hedefinize erişilemedi', html);
    }
    const twoFa = !twoFactor ? '' : de
      ? '<p style="color:#7a2018">Es wird ein Testkonto <strong>ohne 2FA</strong> benötigt; bei Ihrem Konto scheint die Zwei-Faktor-Authentifizierung aktiv zu sein.</p>'
      : '<p style="color:#7a2018"><strong>2FA’sı olmayan</strong> bir test hesabı gerekir; hesabınızda iki-adımlı doğrulama açık görünüyor.</p>';
    const body = de
      ? `<p>Beim authentifizierten Scan für <strong>${esc(o.domain.hostname)}</strong> war mit dem angegebenen Testkonto <strong>keine Anmeldung möglich</strong>.</p>
      <p>Bitte prüfen Sie Benutzername/Passwort (und deaktivieren Sie ggf. 2FA) und versuchen Sie es erneut.</p>
      ${twoFa}
      <p style="margin-top:12px;padding:10px 14px;background:#f3f7f6;border-left:3px solid #123F3A;border-radius:6px;color:#3a4a47;font-size:13px">
        Mit korrekten Zugangsdaten können Sie den Scan <strong>erneut starten</strong>. Für eine Erstattung oder erneute Ausführung kontaktieren Sie uns unter <a href="mailto:support@cybertestify.com" style="color:#123F3A;font-weight:600">support@cybertestify.com</a> — wir prüfen Ihr Anliegen persönlich und helfen weiter.
      </p>`
      : `<p><strong>${esc(o.domain.hostname)}</strong> için kimlik-doğrulamalı taramada, verdiğiniz test hesabıyla <strong>giriş yapılamadı</strong>.</p>
      <p>Lütfen kullanıcı adı/şifreyi kontrol edin (ve varsa 2FA’yı kapatın), sonra tekrar deneyin.</p>
      ${twoFa}
      <p style="margin-top:12px;padding:10px 14px;background:#f3f7f6;border-left:3px solid #123F3A;border-radius:6px;color:#3a4a47;font-size:13px">
        Doğru kimlik bilgisiyle taramayı <strong>yeniden başlatabilirsiniz</strong>. Ödemenizin iadesi veya tekrar çalıştırılması için
        <a href="mailto:support@cybertestify.com" style="color:#123F3A;font-weight:600">support@cybertestify.com</a> adresinden bizimle iletişime geçin — talebinizi elden inceleyip yardımcı olalım.
      </p>`;
    const html = layout({ lang, heading: de ? 'Anmeldung fehlgeschlagen' : 'Girişi yapılamadı', bodyHtml: body, cta: { label: de ? 'Bestellung ansehen' : 'Siparişimi görüntüle', url: `${config.frontendUrl}/dashboard/${o.id}` } });
    return await sendMail(o.customer.email, de ? 'Authentifizierter Scan — Anmeldung fehlgeschlagen' : 'Kimlik-doğrulamalı tarama — giriş yapılamadı', html);
  } catch (err) {
    console.error('[mail] sendAuthLoginFailed hata:', err);
    return false;
  }
}

// --- (Fatura talebi — MANUEL) Vedat'a "yeni fatura talebi" bildirimi -----------
// Sistem OTOMATİK e-fatura KESMEZ; bu yalnız Vedat'ı haberdar eder (admin panelde de görünür).
function fmtMoney2(minor: number, currency: string): string {
  try { return new Intl.NumberFormat('tr-TR', { style: 'currency', currency }).format(minor / 100); } catch { return `${(minor / 100).toFixed(2)} ${currency}`; }
}
export async function sendInvoiceRequestNotification(orderId: string): Promise<boolean> {
  try {
    const inv = await prisma.invoiceRequest.findUnique({
      where: { orderId },
      include: { order: { include: { customer: { select: { email: true } }, package: { select: { displayName: true } }, domain: { select: { hostname: true } } } } },
    });
    if (!inv) return false;
    const o = inv.order;
    const rows: Array<[string, string]> = [
      ['Sipariş no', o.id],
      ['Paket', o.package.displayName],
      ['Hedef', o.domain.hostname],
      ['Ödenen tutar', fmtMoney2(o.amountMinorUnit, o.currency)],
      ['Müşteri e-posta', o.customer.email],
      ['Fatura tipi', inv.type === 'kurumsal' ? 'Kurumsal' : 'Bireysel'],
      ...(inv.type === 'kurumsal'
        ? [['Ticari unvan', inv.companyName ?? '-'], ['Vergi dairesi', inv.taxOffice ?? '-'], ['VKN', inv.taxNumber ?? '-']] as Array<[string, string]>
        : [['Ad soyad', inv.fullName ?? '-'], ['TCKN', inv.nationalId ?? '-']] as Array<[string, string]>),
      ['Adres', inv.address],
      ['Fatura e-posta', inv.invoiceEmail],
    ];
    const table = rows.map(([k, v]) => `<tr><td style="padding:6px 10px;color:#8a9794;font-size:13px">${esc(k)}</td><td style="padding:6px 10px;font-size:13px;font-weight:600">${esc(v)}</td></tr>`).join('');
    const body = `<p>Yeni bir <strong>fatura talebi</strong> geldi. Faturayı e-fatura aracınızla elle kesip gönderdikten sonra admin panelinden durumu güncelleyin.</p>
      <table role="presentation" style="width:100%;margin:12px 0;border:1px solid #e3e8e6;border-radius:10px;border-collapse:collapse">${table}</table>`;
    const html = layout({ heading: 'Yeni fatura talebi', bodyHtml: body, cta: config.adminUrl ? { label: 'Admin panelinde aç', url: `${config.adminUrl}/admin/orders` } : undefined });
    return await sendMail(config.invoiceNotifyEmail, `Yeni fatura talebi — ${o.package.displayName}`, html);
  } catch (err) {
    console.error('[mail] sendInvoiceRequestNotification hata:', err);
    return false;
  }
}

// --- (İade talebi) Müşteri iade istedi -> Vedat'a bildirim (admin panelde de görünür) --------
export async function sendRefundRequestNotification(orderId: string): Promise<boolean> {
  try {
    const o = await prisma.order.findUnique({
      where: { id: orderId },
      include: { customer: { select: { email: true } }, package: { select: { displayName: true } }, domain: { select: { hostname: true } } },
    });
    if (!o) return false;
    const promo = await prisma.promoCodeUsage.findUnique({ where: { orderId }, select: { finalAmountMinorUnit: true } });
    const paidMinor = promo ? promo.finalAmountMinorUnit : o.amountMinorUnit;
    const rows: Array<[string, string]> = [
      ['Sipariş no', o.id],
      ['Paket', o.package.displayName],
      ['Hedef', o.domain.hostname],
      ['Ödenen tutar', paidMinor > 0 ? fmtMoney2(paidMinor, o.currency) : `${fmtMoney2(0, o.currency)} (promosyonla ücretsiz)`],
      ['Müşteri e-posta', o.customer.email],
      ['Sipariş durumu', o.status],
      ['Başarısızlık sebebi', o.failureReason ?? '-'],
      ['Deneme sayısı', String(o.attemptCount)],
      ['Talep sebebi', o.refundRequestReason ?? '-'],
    ];
    const table = rows.map(([k, v]) => `<tr><td style="padding:6px 10px;color:#8a9794;font-size:13px">${esc(k)}</td><td style="padding:6px 10px;font-size:13px;font-weight:600">${esc(v)}</td></tr>`).join('');
    const body = `<p>Bir müşteri <strong>iade talebinde</strong> bulundu. iyzico panelinden iadeyi yaptıktan sonra admin panelinden siparişi "İade edildi" olarak işaretleyin.</p>
      <table role="presentation" style="width:100%;margin:12px 0;border:1px solid #e3e8e6;border-radius:10px;border-collapse:collapse">${table}</table>`;
    const html = layout({ heading: 'Yeni iade talebi', bodyHtml: body, cta: config.adminUrl ? { label: 'Admin panelinde aç', url: `${config.adminUrl}/admin/orders` } : undefined });
    return await sendMail(config.invoiceNotifyEmail, `Yeni iade talebi — ${o.package.displayName}`, html);
  } catch (err) {
    console.error('[mail] sendRefundRequestNotification hata:', err);
    return false;
  }
}

// --- (C) Tarama basladi (flow gercekten 'scan_running' oldugunda) -------------
export async function sendScanStarted(orderId: string): Promise<boolean> {
  try {
    const o = await orderWithRelations(orderId);
    if (!o) return false;
    const lang = mailLang(o.locale);
    const body = lang === 'de'
      ? `<p>Ihr Scan <strong>${esc(o.package.displayName)}</strong> für <strong>${esc(o.domain.hostname)}</strong> hat die Warteschlange verlassen und läuft nun.</p>
      <p style="color:#3a4a47">Sobald der Scan abgeschlossen und Ihr Bericht fertig ist, senden wir Ihnen erneut eine E-Mail. Den Status können Sie im Live-Feed Ihres Panels verfolgen.</p>`
      : `<p><strong>${esc(o.domain.hostname)}</strong> için <strong>${esc(o.package.displayName)}</strong> taramanız kuyruktan çıkıp çalışmaya başladı.</p>
      <p style="color:#3a4a47">Tarama tamamlanıp raporunuz hazır olduğunda size tekrar e-posta göndereceğiz. Durumu paneldeki canlı akıştan izleyebilirsiniz.</p>`;
    const html = layout({ lang, heading: lang === 'de' ? 'Ihr Scan hat begonnen' : 'Taramanız başladı', bodyHtml: body, cta: { label: lang === 'de' ? 'Live-Status verfolgen' : 'Canlı durumu izle', url: `${config.frontendUrl}/dashboard/${o.id}` } });
    return await sendMail(o.customer.email, lang === 'de' ? 'Ihr Scan hat begonnen — CyberTestify' : 'Taramanız başladı — CyberTestify', html);
  } catch (err) {
    console.error('[mail] sendScanStarted hata:', err);
    return false;
  }
}

// --- (D) Rapor hazir + erisim sifresi -----------------------------------------
export async function sendReportReady(orderId: string, accessSecret: string): Promise<boolean> {
  try {
    const o = await orderWithRelations(orderId);
    if (!o) return false;
    const lang = mailLang(o.locale);
    const body = lang === 'de'
      ? `<p>Ihr Bericht <strong>${esc(o.package.displayName)}</strong> für <strong>${esc(o.domain.hostname)}</strong> ist fertig.</p>
      <p style="color:#3a4a47">Der Bericht ist zu Ihrer Sicherheit verschlüsselt. Nach der Anmeldung im Panel müssen Sie beim Herunterladen den folgenden <strong>Zugangscode</strong> eingeben:</p>
      <p style="margin:14px 0;padding:14px 16px;background:#f2f7f5;border:1px dashed #1C6B60;border-radius:10px;text-align:center">
        <span style="font-size:12px;color:#8a9794;display:block;margin-bottom:4px">Ihr Bericht-Zugangscode</span>
        <span style="font-family:ui-monospace,Menlo,Consolas,monospace;font-size:20px;font-weight:800;letter-spacing:1px;color:#123F3A">${esc(accessSecret)}</span>
      </p>
      <p style="color:#8a9794;font-size:12px">Teilen Sie diesen Code mit niemandem. Er wird nur für den Zugriff auf diesen Bericht benötigt.</p>`
      : `<p><strong>${esc(o.domain.hostname)}</strong> için <strong>${esc(o.package.displayName)}</strong> raporunuz hazır.</p>
      <p style="color:#3a4a47">Rapor güvenliğiniz için şifrelidir. Panele giriş yaptıktan sonra raporu indirirken aşağıdaki <strong>erişim şifresini</strong> girmeniz gerekir:</p>
      <p style="margin:14px 0;padding:14px 16px;background:#f2f7f5;border:1px dashed #1C6B60;border-radius:10px;text-align:center">
        <span style="font-size:12px;color:#8a9794;display:block;margin-bottom:4px">Rapor erişim şifreniz</span>
        <span style="font-family:ui-monospace,Menlo,Consolas,monospace;font-size:20px;font-weight:800;letter-spacing:1px;color:#123F3A">${esc(accessSecret)}</span>
      </p>
      <p style="color:#8a9794;font-size:12px">Bu şifreyi kimseyle paylaşmayın. Yalnızca bu rapora erişim için gereklidir.</p>`;
    const html = layout({ lang, heading: lang === 'de' ? 'Ihr Bericht ist fertig' : 'Raporunuz hazır', bodyHtml: body, cta: { label: lang === 'de' ? 'Bericht ansehen' : 'Raporu görüntüle', url: `${config.frontendUrl}/dashboard/${o.id}` } });
    return await sendMail(o.customer.email, lang === 'de' ? 'Ihr Bericht ist fertig — CyberTestify' : 'Raporunuz hazır — CyberTestify', html);
  } catch (err) {
    console.error('[mail] sendReportReady hata:', err);
    return false;
  }
}

// --- (E) Iade bildirimi (admin-tetiklemeli) -----------------------------------
export async function sendRefundNotice(orderId: string): Promise<boolean> {
  try {
    const o = await orderWithRelations(orderId);
    if (!o) return false;
    // GERÇEKTEN ÖDENEN tutar: promo kullanıldıysa PromoCodeUsage.finalAmountMinorUnit (100% promo -> 0);
    // yoksa order.amountMinorUnit. Bundle'da amountMinorUnit tam fiyat tutulur ama promo'yla 0 ödenmiş
    // olabilir -> promo usage'a bak (yanlış "22.999" iade göstermesin).
    const promo = await prisma.promoCodeUsage.findUnique({ where: { orderId }, select: { finalAmountMinorUnit: true } });
    const paidMinor = promo ? promo.finalAmountMinorUnit : o.amountMinorUnit;
    const lang = mailLang(o.locale);
    const de = lang === 'de';
    const refundRow = paidMinor > 0
      ? `<tr><td style="padding:12px 14px;font-size:13px;color:#8a9794">${de ? 'Erstattungsbetrag' : 'İade tutarı'}</td><td style="padding:12px 14px;font-size:16px;font-weight:800;color:#123F3A;text-align:right">${fmtMoney(paidMinor, o.currency, lang)}</td></tr>`
      : `<tr><td style="padding:12px 14px;font-size:13px;color:#8a9794">${de ? 'Gezahlter Betrag' : 'Ödenen tutar'}</td><td style="padding:12px 14px;font-size:14px;font-weight:700;color:#123F3A;text-align:right">${fmtMoney(0, o.currency, lang)} ${de ? '(kostenlos per Aktionscode)' : '(promosyonla ücretsiz)'}</td></tr>`;
    const intro = de
      ? (paidMinor > 0
        ? `<p>Der Betrag Ihrer Bestellung <strong>${esc(o.package.displayName)}</strong> für <strong>${esc(o.domain.hostname)}</strong> wurde erstattet.</p>`
        : `<p>Ihre Bestellung <strong>${esc(o.package.displayName)}</strong> für <strong>${esc(o.domain.hostname)}</strong> wurde storniert. Da sie <strong>kostenlos per Aktionscode</strong> erstellt wurde, gibt es keine zu erstattende Zahlung.</p>`)
      : (paidMinor > 0
        ? `<p><strong>${esc(o.domain.hostname)}</strong> için <strong>${esc(o.package.displayName)}</strong> siparişinizin bedeli iade edilmiştir.</p>`
        : `<p><strong>${esc(o.domain.hostname)}</strong> için <strong>${esc(o.package.displayName)}</strong> siparişiniz iptal edilmiştir. Bu sipariş <strong>promosyon koduyla ücretsiz</strong> oluşturulduğundan iade edilecek bir ödeme bulunmamaktadır.</p>`);
    const tail = paidMinor > 0
      ? (de
        ? `<p style="color:#3a4a47">Die Gutschrift des Erstattungsbetrags auf Ihre Karte/Ihr Konto kann je nach Bank einige Werktage dauern.</p>`
        : `<p style="color:#3a4a47">İade tutarının kartınıza/hesabınıza yansıması, bankanıza bağlı olarak birkaç iş günü sürebilir.</p>`)
      : '';
    const body = `${intro}
      <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;margin:12px 0;border:1px solid #e3e8e6;border-radius:10px">
        <tr><td style="padding:12px 14px;border-bottom:1px solid #eef2f1;font-size:13px;color:#8a9794">${de ? 'Bestellnummer' : 'Sipariş no'}</td><td style="padding:12px 14px;border-bottom:1px solid #eef2f1;font-size:13px;text-align:right">${esc(o.id.slice(0, 8))}</td></tr>
        ${refundRow}
      </table>
      ${tail}`;
    const html = layout({ lang, heading: de ? (paidMinor > 0 ? 'Ihre Erstattung wurde durchgeführt' : 'Ihre Bestellung wurde storniert') : (paidMinor > 0 ? 'İadeniz gerçekleştirildi' : 'Siparişiniz iptal edildi'), bodyHtml: body });
    return await sendMail(o.customer.email, de ? 'Erstattungsmitteilung — CyberTestify' : 'İade bildirimi — CyberTestify', html);
  } catch (err) {
    console.error('[mail] sendRefundNotice hata:', err);
    return false;
  }
}
