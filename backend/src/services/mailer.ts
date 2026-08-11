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
function fmtMoney(minor: number, currency: string): string {
  const v = (minor / 100).toLocaleString('tr-TR', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  return `${v} ${currency === 'TRY' ? 'TL' : currency}`;
}
function esc(s: string): string {
  return String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] as string));
}

/** Ortak marka cercevesi (inline stil — e-posta istemcileri uyumlu). */
function layout(opts: { heading: string; bodyHtml: string; cta?: { label: string; url: string } }): string {
  const cta = opts.cta
    ? `<tr><td style="padding:8px 0 4px"><a href="${esc(opts.cta.url)}" style="display:inline-block;background:#F5A623;color:#123F3A;font-weight:700;text-decoration:none;padding:12px 22px;border-radius:999px;font-size:15px">${esc(opts.cta.label)}</a></td></tr>`
    : '';
  return `<!doctype html><html lang="tr"><body style="margin:0;background:#f4f6f5;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1c2b28">
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
       <p style="margin:0;font-size:11px;color:#8a9794;line-height:1.5">
         Bu e-posta CyberTestify tarafından otomatik gönderilmiştir. Sorularınız için
         <a href="mailto:destek@cybertestify.com" style="color:#1C6B60">destek@cybertestify.com</a>.<br>
         CyberTestify — dijital güvenlik ön-değerlendirme hizmeti.
       </p>
     </td></tr>
    </table>
   </td></tr>
  </table>
 </body></html>`;
}

async function orderWithRelations(orderId: string) {
  return prisma.order.findUnique({
    where: { id: orderId },
    include: { customer: { select: { email: true, fullName: true } }, package: { select: { displayName: true } }, domain: { select: { hostname: true } } },
  });
}

// --- (0) E-posta dogrulama kodu (kayit sonrasi) -------------------------------
export async function sendEmailVerification(email: string, code: string): Promise<boolean> {
  const html = layout({
    heading: 'E-posta adresinizi doğrulayın',
    bodyHtml: `<p>CyberTestify'a hoş geldiniz. Hesabınızı etkinleştirmek ve satın alma yapabilmek için aşağıdaki doğrulama kodunu girin:</p>
      <p style="margin:16px 0;padding:16px;background:#f2f7f5;border:1px dashed #1C6B60;border-radius:10px;text-align:center">
        <span style="font-family:ui-monospace,Menlo,Consolas,monospace;font-size:30px;font-weight:800;letter-spacing:6px;color:#123F3A">${esc(code)}</span>
      </p>
      <p style="color:#8a9794;font-size:13px">Kod <strong>15 dakika</strong> geçerlidir. Bu talebi siz yapmadıysanız bu e-postayı yok sayabilirsiniz.</p>`,
  });
  return sendMail(email, 'Doğrulama kodunuz — CyberTestify', html);
}

// --- (A) Sifre sifirlama ------------------------------------------------------
export async function sendPasswordReset(email: string, resetUrl: string): Promise<boolean> {
  const html = layout({
    heading: 'Şifre sıfırlama talebi',
    bodyHtml: `<p>Hesabınız için şifre sıfırlama talebinde bulunuldu. Yeni şifrenizi belirlemek için aşağıdaki butona tıklayın.</p>
      <p style="color:#8a9794;font-size:13px">Bu bağlantı <strong>1 saat</strong> geçerlidir ve yalnızca bir kez kullanılabilir. Bu talebi siz yapmadıysanız bu e-postayı yok sayabilirsiniz; şifreniz değişmez.</p>`,
    cta: { label: 'Şifremi sıfırla', url: resetUrl },
  });
  return sendMail(email, 'Şifre sıfırlama — CyberTestify', html);
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
    const totalMinor = orders.reduce((s, o) => s + o.amountMinorUnit, 0);
    const isBundle = orders.length > 1;
    const items = orders.map((o) => `<li style="margin:2px 0">${esc(o.package.displayName)}</li>`).join('');
    const orderRef = orders.map((o) => o.id.slice(0, 8)).join(', ');
    // Aktif Doğrulama Paketi ise: satın alma ANINDA yazılı kapsam netliği (login’siz yüzey).
    const isActiveVerify = orders.some((o) => ACTIVE_VERIFY_KEYS.has(o.package.key));
    const scopeNote = isActiveVerify
      ? `<p style="margin:12px 0;padding:10px 14px;background:#f3f7f6;border-left:3px solid #123F3A;border-radius:6px;color:#3a4a47;font-size:13px"><strong>Kapsam:</strong> Bu paket kimlik doğrulaması gerektirmeyen (login olmadan test edilebilen) yüzeyde çalışır. Login sonrası ortaya çıkan derin yetkilendirme/iş mantığı zafiyetleri bu paketin kapsamı dışındadır; sonuçlar hedefin yapısına göre değişir.</p>`
      : '';
    // (Tam Kapsamlı Pentest — FAZ A) Kimlik-doğrulamalı paket: satın alma anında yazılı "test hesabı" uyarısı.
    const isAuthenticated = orders.some((o) => requiresTestCredentials(o.package.key));
    const credWarn = isAuthenticated
      ? `<p style="margin:12px 0;padding:10px 14px;background:#fff5f5;border-left:3px solid #c0392b;border-radius:6px;color:#7a2018;font-size:13px"><strong>⚠️ Test hesabı:</strong> Bu paket kimlik-doğrulamalı (login’li) test içerir. Lütfen üretim/ana hesabınızı DEĞİL; sınırlı yetkili, tek-kullanımlık, 2FA’sı olmayan bir TEST hesabı kullanın ve şifresini tarama sonrası değiştirin. Kimlik bilgileriniz şifreli saklanır ve tarama sonrası silinir.</p>`
      : '';
    // (İŞ 4/5) full_pentest artık ödeme sonrası DİREKT başlar (manuel inceleme kalktı). Alıcıya yalnız
    // dürüst kapsam/beklenti notu: yapay zekâ destekli analiz katmanı + cross-account kapsam dışı.
    const isFullPentest = orders.some((o) => o.package.key === 'bundle_full_pentest');
    const reviewNote = isFullPentest
      ? `<p style="margin:12px 0;padding:10px 14px;background:#f3f7f6;border-left:3px solid #123F3A;border-radius:6px;color:#3a4a47;font-size:13px"><strong>Kapsam & beklenti:</strong> Bu paket deterministik kimlik-doğrulamalı kontroller + iki kontrolde <strong>yapay zekâ destekli analiz</strong> kullanır (tek LLM danışma çağrısı; otonom/sınırsız pentest değildir). Cross-account (başka bir kullanıcının verisine erişim) IDOR bu sürümün kapsamı dışındadır. Yapay zekâ destekli analiz katmanı bazı hedeflerde uygulanabilir bir gösterge bulamayabilir; bu durumda sonuçlar deterministik authenticated kontrollerle sınırlı kalır — bu normaldir ve rapor bunu şeffaf gösterir.</p>`
      : '';
    const body = `<p>Siparişiniz alındı ve ödemeniz onaylandı. Teşekkür ederiz.</p>
      <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;margin:12px 0;border:1px solid #e3e8e6;border-radius:10px">
        <tr><td style="padding:12px 14px;border-bottom:1px solid #eef2f1;font-size:13px;color:#8a9794">Hedef</td><td style="padding:12px 14px;border-bottom:1px solid #eef2f1;font-size:14px;font-weight:600;text-align:right">${esc(hostname)}</td></tr>
        <tr><td style="padding:12px 14px;border-bottom:1px solid #eef2f1;font-size:13px;color:#8a9794;vertical-align:top">${isBundle ? 'Paket içeriği' : 'Paket'}</td><td style="padding:12px 14px;border-bottom:1px solid #eef2f1;font-size:14px;font-weight:600;text-align:right"><ul style="margin:0;padding:0;list-style:none">${items}</ul></td></tr>
        <tr><td style="padding:12px 14px;border-bottom:1px solid #eef2f1;font-size:13px;color:#8a9794">Sipariş no</td><td style="padding:12px 14px;border-bottom:1px solid #eef2f1;font-size:13px;text-align:right">${esc(orderRef)}</td></tr>
        <tr><td style="padding:12px 14px;font-size:13px;color:#8a9794">Tutar</td><td style="padding:12px 14px;font-size:16px;font-weight:800;color:#123F3A;text-align:right">${fmtMoney(totalMinor, currency)}</td></tr>
      </table>
      ${reviewNote}${credWarn}${scopeNote}<p style="color:#3a4a47">Taramanız sıraya alındı. <strong>Başladığında</strong> size ayrıca bir e-posta göndereceğiz; durumu panelinizden de takip edebilirsiniz.</p>`;
    const html = layout({ heading: 'Siparişiniz alındı', bodyHtml: body, cta: { label: 'Siparişimi görüntüle', url: `${config.frontendUrl}/dashboard/${orders[0].id}` } });
    return await sendMail(email, 'Siparişiniz alındı — CyberTestify', html);
  } catch (err) {
    console.error('[mail] sendOrderConfirmation hata:', err);
    return false;
  }
}

// --- (Tam Kapsamlı Pentest — FAZ B) Login başarısız bildirimi (kredi YOK — İŞ 2) ------
export async function sendAuthLoginFailed(orderId: string, twoFactor: boolean): Promise<boolean> {
  try {
    const o = await prisma.order.findUnique({
      where: { id: orderId },
      include: { customer: { select: { email: true } }, domain: { select: { hostname: true } } },
    });
    if (!o) return false;
    const twoFa = twoFactor
      ? '<p style="color:#7a2018"><strong>2FA’sı olmayan</strong> bir test hesabı gerekir; hesabınızda iki-adımlı doğrulama açık görünüyor.</p>'
      : '';
    const body = `<p><strong>${esc(o.domain.hostname)}</strong> için kimlik-doğrulamalı taramada, verdiğiniz test hesabıyla <strong>giriş yapılamadı</strong>.</p>
      <p>Lütfen kullanıcı adı/şifreyi kontrol edin (ve varsa 2FA’yı kapatın), sonra tekrar deneyin.</p>
      ${twoFa}
      <p style="margin-top:12px;padding:10px 14px;background:#f3f7f6;border-left:3px solid #123F3A;border-radius:6px;color:#3a4a47;font-size:13px">
        Doğru kimlik bilgisiyle taramayı <strong>yeniden başlatabilirsiniz</strong>. Ödemenizin iadesi veya tekrar çalıştırılması için
        <a href="mailto:support@cybertestify.com" style="color:#123F3A;font-weight:600">support@cybertestify.com</a> adresinden bizimle iletişime geçin — talebinizi elden inceleyip yardımcı olalım.
      </p>`;
    const html = layout({ heading: 'Girişi yapılamadı', bodyHtml: body, cta: { label: 'Siparişimi görüntüle', url: `${config.frontendUrl}/dashboard/${o.id}` } });
    return await sendMail(o.customer.email, 'Kimlik-doğrulamalı tarama — giriş yapılamadı', html);
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

// --- (C) Tarama basladi (flow gercekten 'scan_running' oldugunda) -------------
export async function sendScanStarted(orderId: string): Promise<boolean> {
  try {
    const o = await orderWithRelations(orderId);
    if (!o) return false;
    const body = `<p><strong>${esc(o.domain.hostname)}</strong> için <strong>${esc(o.package.displayName)}</strong> taramanız kuyruktan çıkıp çalışmaya başladı.</p>
      <p style="color:#3a4a47">Tarama tamamlanıp raporunuz hazır olduğunda size tekrar e-posta göndereceğiz. Durumu paneldeki canlı akıştan izleyebilirsiniz.</p>`;
    const html = layout({ heading: 'Taramanız başladı', bodyHtml: body, cta: { label: 'Canlı durumu izle', url: `${config.frontendUrl}/dashboard/${o.id}` } });
    return await sendMail(o.customer.email, 'Taramanız başladı — CyberTestify', html);
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
    const body = `<p><strong>${esc(o.domain.hostname)}</strong> için <strong>${esc(o.package.displayName)}</strong> raporunuz hazır.</p>
      <p style="color:#3a4a47">Rapor güvenliğiniz için şifrelidir. Panele giriş yaptıktan sonra raporu indirirken aşağıdaki <strong>erişim şifresini</strong> girmeniz gerekir:</p>
      <p style="margin:14px 0;padding:14px 16px;background:#f2f7f5;border:1px dashed #1C6B60;border-radius:10px;text-align:center">
        <span style="font-size:12px;color:#8a9794;display:block;margin-bottom:4px">Rapor erişim şifreniz</span>
        <span style="font-family:ui-monospace,Menlo,Consolas,monospace;font-size:20px;font-weight:800;letter-spacing:1px;color:#123F3A">${esc(accessSecret)}</span>
      </p>
      <p style="color:#8a9794;font-size:12px">Bu şifreyi kimseyle paylaşmayın. Yalnızca bu rapora erişim için gereklidir.</p>`;
    const html = layout({ heading: 'Raporunuz hazır', bodyHtml: body, cta: { label: 'Raporu görüntüle', url: `${config.frontendUrl}/dashboard/${o.id}` } });
    return await sendMail(o.customer.email, 'Raporunuz hazır — CyberTestify', html);
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
    const body = `<p><strong>${esc(o.domain.hostname)}</strong> için <strong>${esc(o.package.displayName)}</strong> siparişinizin bedeli iade edilmiştir.</p>
      <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;margin:12px 0;border:1px solid #e3e8e6;border-radius:10px">
        <tr><td style="padding:12px 14px;border-bottom:1px solid #eef2f1;font-size:13px;color:#8a9794">Sipariş no</td><td style="padding:12px 14px;border-bottom:1px solid #eef2f1;font-size:13px;text-align:right">${esc(o.id.slice(0, 8))}</td></tr>
        <tr><td style="padding:12px 14px;font-size:13px;color:#8a9794">İade tutarı</td><td style="padding:12px 14px;font-size:16px;font-weight:800;color:#123F3A;text-align:right">${fmtMoney(o.amountMinorUnit, o.currency)}</td></tr>
      </table>
      <p style="color:#3a4a47">İade tutarının kartınıza/hesabınıza yansıması, bankanıza bağlı olarak birkaç iş günü sürebilir.</p>`;
    const html = layout({ heading: 'İadeniz gerçekleştirildi', bodyHtml: body });
    return await sendMail(o.customer.email, 'İade bildirimi — CyberTestify', html);
  } catch (err) {
    console.error('[mail] sendRefundNotice hata:', err);
    return false;
  }
}
