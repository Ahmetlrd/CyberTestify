'use client';

import { useState } from 'react';
import { api } from '../../lib/api';

/**
 * (Başarısız tarama) Kullanıcıya NET sebep + aksiyon. ≤2 denemede "Tekrar Dene" (kimlik-doğrulamalı
 * pakette yeni test hesabı bilgisi ister), >2 denemede tek "İade talebinde bulun" butonu (admin görür).
 */
const SF = {
  tr: {
    fmDefault: 'Tarama tamamlanamadı. Tekrar deneyebilirsiniz.',
    fmUnreachable: 'Taramanız sırasında sitenize erişilemedi (sunucu hata/erişilemez durum döndürdü) — bu kullanıcı adı/şifre sorunu DEĞİLDİR, giriş denemesi bile yapılmadı. Sitenizin şu an yayında olduğundan emin olup tekrar deneyin (test hesabı bilgileriniz hâlâ kayıtlı).',
    fm2fa: 'Verdiğiniz test hesabında iki-adımlı doğrulama (2FA) açık göründüğü için giriş yapılamadı. 2FA’sız, sınırlı yetkili bir TEST hesabıyla tekrar deneyin.',
    fmAuth: 'Verdiğiniz test hesabıyla giriş yapılamadı — kullanıcı adı/şifre hatalı olabilir. Bilgileri kontrol edip yeniden girerek tekrar deneyin.',
    fmGen: 'Tarama sırasında beklenmeyen bir hata oluştu. Tekrar deneyebilirsiniz.',
    fmInterrupted: 'Tarama beklenmedik şekilde kesildi (ör. bakım). Tekrar deneyebilirsiniz.',
    refundReceivedPre: 'İade talebiniz alındı.', refundReceivedBody: ' Bu sipariş için talebiniz kaydedildi; ekibimiz inceleyip en kısa sürede sizinle iletişime geçecek ve iadenizi işleme alacaktır. Yeni bir talep göndermenize gerek yok. Sorunuz varsa ', refundReceivedPost: ' ile iletişime geçebilirsiniz.',
    failedTitle: 'Tarama tamamlanamadı',
    credUser: 'Test hesabı kullanıcı adı', credPass: 'Test hesabı şifresi',
    needCredsErr: 'Bu paket kimlik-doğrulamalı test içerir; devam etmek için test hesabı bilgilerini girin.',
    retrying: 'Deneniyor…', retry: 'Tekrar Dene', starting: 'Başlatılıyor…', loginless: 'Loginsiz devam et',
    insteadRefund: 'Bunun yerine iade talebinde bulun',
    loginlessHintHtml: 'Sitenizde giriş (login) yoksa <strong>“Loginsiz devam et”</strong> ile tarama kimlik-doğrulaması olmadan çalışır; oturum-içi kontroller raporda “kapsam dışı” görünür.',
    tooMany: 'Bu tarama birden çok kez denendi. Dilerseniz iade talebinde bulunabilirsiniz; ekibimiz işleme alacaktır.',
    refundReasonPh: 'İade sebebiniz (opsiyonel)', sending: 'Gönderiliyor…', requestRefund: 'İade talebinde bulun',
    errRetry: 'Tekrar denenemedi.', errLoginless: 'Loginsiz devam edilemedi.', errRefund: 'İade talebi gönderilemedi.',
  },
  de: {
    fmDefault: 'Der Scan konnte nicht abgeschlossen werden. Sie können es erneut versuchen.',
    fmUnreachable: 'Während Ihres Scans war Ihre Website nicht erreichbar (der Server lieferte einen Fehler-/Nicht-erreichbar-Status) — dies ist KEIN Problem mit Benutzername/Passwort, es wurde nicht einmal ein Login-Versuch unternommen. Stellen Sie sicher, dass Ihre Website derzeit online ist, und versuchen Sie es erneut (Ihre Testkonto-Daten sind weiterhin gespeichert).',
    fm2fa: 'Beim angegebenen Testkonto scheint die Zwei-Faktor-Authentifizierung (2FA) aktiviert zu sein, daher war keine Anmeldung möglich. Versuchen Sie es mit einem TEST-Konto ohne 2FA und eingeschränkten Rechten erneut.',
    fmAuth: 'Mit dem angegebenen Testkonto war keine Anmeldung möglich — Benutzername/Passwort könnten falsch sein. Prüfen Sie die Daten, geben Sie sie erneut ein und versuchen Sie es noch einmal.',
    fmGen: 'Während des Scans ist ein unerwarteter Fehler aufgetreten. Sie können es erneut versuchen.',
    fmInterrupted: 'Der Scan wurde unerwartet unterbrochen (z. B. Wartung). Sie können es erneut versuchen.',
    refundReceivedPre: 'Ihre Erstattungsanfrage ist eingegangen.', refundReceivedBody: ' Ihre Anfrage für diese Bestellung wurde erfasst; unser Team prüft sie und wird sich in Kürze bei Ihnen melden und die Erstattung bearbeiten. Sie müssen keine neue Anfrage senden. Bei Fragen erreichen Sie uns unter ', refundReceivedPost: '.',
    failedTitle: 'Scan konnte nicht abgeschlossen werden',
    credUser: 'Testkonto-Benutzername', credPass: 'Testkonto-Passwort',
    needCredsErr: 'Dieses Paket enthält authentifizierte Tests; geben Sie die Testkonto-Daten ein, um fortzufahren.',
    retrying: 'Wird versucht…', retry: 'Erneut versuchen', starting: 'Wird gestartet…', loginless: 'Ohne Login fortfahren',
    insteadRefund: 'Stattdessen eine Erstattung anfordern',
    loginlessHintHtml: 'Wenn Ihre Website keinen Login hat, läuft der Scan mit <strong>„Ohne Login fortfahren“</strong> ohne Authentifizierung; sitzungsinterne Prüfungen erscheinen im Bericht als „außerhalb des Scope“.',
    tooMany: 'Dieser Scan wurde mehrfach versucht. Sie können eine Erstattung anfordern; unser Team wird sie bearbeiten.',
    refundReasonPh: 'Ihr Erstattungsgrund (optional)', sending: 'Wird gesendet…', requestRefund: 'Erstattung anfordern',
    errRetry: 'Erneuter Versuch fehlgeschlagen.', errLoginless: 'Fortfahren ohne Login nicht möglich.', errRefund: 'Erstattungsanfrage konnte nicht gesendet werden.',
  },
  en: {
    fmDefault: 'The scan could not be completed. You can try again.',
    fmUnreachable: 'During your scan, your website was unreachable (the server returned an error/unreachable status) — this is NOT a username/password issue; no login attempt was even made. Make sure your site is currently online and try again (your test-account details are still saved).',
    fm2fa: 'The test account you provided appears to have two-factor authentication (2FA) enabled, so sign-in was not possible. Please try again with a TEST account without 2FA and with limited privileges.',
    fmAuth: 'Sign-in with the test account you provided failed — the username/password may be incorrect. Check the details, re-enter them, and try again.',
    fmGen: 'An unexpected error occurred during the scan. You can try again.',
    fmInterrupted: 'The scan was interrupted unexpectedly (e.g. maintenance). You can try again.',
    refundReceivedPre: 'Your refund request has been received.', refundReceivedBody: ' Your request for this order has been recorded; our team will review it and contact you shortly to process your refund. You do not need to submit a new request. If you have any questions, you can reach us at ', refundReceivedPost: '.',
    failedTitle: 'Scan could not be completed',
    credUser: 'Test account username', credPass: 'Test account password',
    needCredsErr: 'This package includes authenticated testing; enter the test-account details to continue.',
    retrying: 'Retrying…', retry: 'Try again', starting: 'Starting…', loginless: 'Continue without login',
    insteadRefund: 'Request a refund instead',
    loginlessHintHtml: 'If your site has no login, <strong>“Continue without login”</strong> runs the scan without authentication; in-session checks appear in the report as “out of scope”.',
    tooMany: 'This scan has been attempted several times. If you wish, you can request a refund; our team will process it.',
    refundReasonPh: 'Your reason for the refund (optional)', sending: 'Sending…', requestRefund: 'Request a refund',
    errRetry: 'Retry failed.', errLoginless: 'Could not continue without login.', errRefund: 'The refund request could not be sent.',
  },
} as const;

function failureMessage(reason: string | null | undefined, s: { fmDefault: string; fmUnreachable: string; fm2fa: string; fmAuth: string; fmGen: string; fmInterrupted: string }): string {
  if (!reason) return s.fmDefault;
  if (reason.startsWith('auth_login_failed:target_unreachable')) return s.fmUnreachable;
  if (reason.startsWith('auth_login_failed:two_factor')) return s.fm2fa;
  if (reason.startsWith('auth_login_failed')) return s.fmAuth;
  if (reason === 'report_generation_error') return s.fmGen;
  if (reason === 'scan_interrupted') return s.fmInterrupted;
  return s.fmDefault;
}

export function ScanFailedActions({
  orderId, packageKey, attemptCount, failureReason, refundRequestedAt, onRetry, lang = 'tr',
}: {
  orderId: string;
  packageKey?: string;
  attemptCount: number;
  failureReason?: string | null;
  refundRequestedAt?: string | null;
  onRetry: () => void;
  lang?: 'tr' | 'de' | 'en';
}) {
  const s = SF[lang === 'de' ? 'de' : lang === 'en' ? 'en' : 'tr'];
  const tooMany = attemptCount > 2;
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [needCreds, setNeedCreds] = useState(false);
  const [user, setUser] = useState('');
  const [pass, setPass] = useState('');
  // İade talebi bu oturumda gönderildi VEYA sunucuda zaten kayıtlı (sayfa yenilense de kalıcı).
  const [refundDone, setRefundDone] = useState(false);
  const [refundReason, setRefundReason] = useState('');
  const alreadyRefunded = refundDone || !!refundRequestedAt;

  async function retry() {
    setBusy(true); setErr(null);
    try {
      await api.retryScan(orderId, needCreds ? { username: user.trim(), password: pass } : undefined);
      onRetry();
    } catch (e: any) {
      if (e?.needsCredentials) { setNeedCreds(true); setErr(s.needCredsErr); }
      else setErr(e?.message ?? s.errRetry);
    } finally { setBusy(false); }
  }

  // (LOGİNSİZ TEST) Login sağlanamadı → kullanıcı login OLMADAN devam edebilir: tarama unauthenticated
  // (herkese açık) yüzeyle yeniden koşar; oturum-içi kontroller raporda "kapsam dışı" görünür.
  async function retryLoginless() {
    setBusy(true); setErr(null);
    try {
      await api.retryScan(orderId, { loginless: true });
      onRetry();
    } catch (e: any) {
      setErr(e?.message ?? s.errLoginless);
    } finally { setBusy(false); }
  }
  // Login kaynaklı başarısızlık mı (auth başarısız / giriş formu yok)? Öyleyse loginsiz-devam sun.
  // target_unreachable HARİÇ: o durumda hedefin TAMAMI erişilemezdi (giriş hiç denenmedi) — loginsiz
  // devam da aynı şekilde başarısız olur; doğru aksiyon "Tekrar Dene" (hedef ayağa kalkınca).
  const isTargetUnreachable = !!failureReason?.startsWith('auth_login_failed:target_unreachable');
  const isLoginFailure = !isTargetUnreachable && (needCreds || !!(failureReason && (failureReason.startsWith('auth_login_failed') || failureReason === 'no_login_endpoint')));

  async function requestRefund() {
    setBusy(true); setErr(null);
    try {
      await api.requestRefund(orderId, refundReason.trim() || undefined);
      setRefundDone(true);
    } catch (e: any) { setErr(e?.message ?? s.errRefund); }
    finally { setBusy(false); }
  }

  if (alreadyRefunded) {
    return (
      <div className="mt-6 rounded-card border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">
        <strong>{s.refundReceivedPre}</strong>{s.refundReceivedBody}
        <a href="mailto:support@cybertestify.com" className="font-semibold underline">support@cybertestify.com</a>
        {s.refundReceivedPost}
      </div>
    );
  }

  return (
    <div className="mt-6 rounded-card border border-red-200 bg-red-50 px-4 py-4 text-sm text-red-800">
      <p className="font-semibold">{s.failedTitle}</p>
      <p className="mt-1 text-red-700">{failureMessage(failureReason, s)}</p>

      {!tooMany ? (
        <>
          {needCreds && (
            <div className="mt-3 grid gap-2 sm:grid-cols-2">
              <input className="field" placeholder={s.credUser} value={user} onChange={(e) => setUser(e.target.value)} autoComplete="off" />
              <input className="field" type="password" placeholder={s.credPass} value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="new-password" />
            </div>
          )}
          {err && <p className="mt-2 text-xs font-semibold text-red-700">{err}</p>}
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <button
              onClick={retry}
              disabled={busy || (needCreds && (!user.trim() || !pass))}
              className="btn-primary disabled:opacity-60"
            >
              {busy ? s.retrying : s.retry}
            </button>
            {/* (LOGİNSİZ TEST) Login sağlanamayan pakette: kimlik-doğrulaması olmadan devam et. */}
            {isLoginFailure && (
              <button onClick={retryLoginless} disabled={busy} className="btn-dark disabled:opacity-60">
                {busy ? s.starting : s.loginless}
              </button>
            )}
            <button onClick={requestRefund} disabled={busy} className="text-xs font-medium text-red-700 underline">
              {s.insteadRefund}
            </button>
          </div>
          {isLoginFailure && (
            <p className="mt-2 text-xs text-red-700/80" dangerouslySetInnerHTML={{ __html: s.loginlessHintHtml }} />
          )}
        </>
      ) : (
        <>
          <p className="mt-2 text-xs text-red-700">{s.tooMany}</p>
          <textarea className="field mt-2 min-h-[60px] w-full" placeholder={s.refundReasonPh} value={refundReason} onChange={(e) => setRefundReason(e.target.value)} />
          {err && <p className="mt-2 text-xs font-semibold text-red-700">{err}</p>}
          <button onClick={requestRefund} disabled={busy} className="btn-primary mt-2 disabled:opacity-60">
            {busy ? s.sending : s.requestRefund}
          </button>
        </>
      )}
    </div>
  );
}
