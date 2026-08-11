'use client';

import { useState } from 'react';
import { api } from '../../lib/api';

/**
 * (Başarısız tarama) Kullanıcıya NET sebep + aksiyon. ≤2 denemede "Tekrar Dene" (kimlik-doğrulamalı
 * pakette yeni test hesabı bilgisi ister), >2 denemede tek "İade talebinde bulun" butonu (admin görür).
 */
function failureMessage(reason?: string | null): string {
  if (!reason) return 'Tarama tamamlanamadı. Tekrar deneyebilirsiniz.';
  if (reason.startsWith('auth_login_failed:two_factor'))
    return 'Verdiğiniz test hesabında iki-adımlı doğrulama (2FA) açık göründüğü için giriş yapılamadı. 2FA’sız, sınırlı yetkili bir TEST hesabıyla tekrar deneyin.';
  if (reason.startsWith('auth_login_failed'))
    return 'Verdiğiniz test hesabıyla giriş yapılamadı — kullanıcı adı/şifre hatalı olabilir. Bilgileri kontrol edip yeniden girerek tekrar deneyin.';
  if (reason === 'report_generation_error')
    return 'Tarama sırasında beklenmeyen bir hata oluştu. Tekrar deneyebilirsiniz.';
  if (reason === 'scan_interrupted')
    return 'Tarama beklenmedik şekilde kesildi (ör. bakım). Tekrar deneyebilirsiniz.';
  return 'Tarama tamamlanamadı. Tekrar deneyebilirsiniz.';
}

export function ScanFailedActions({
  orderId, packageKey, attemptCount, failureReason, onRetry,
}: {
  orderId: string;
  packageKey?: string;
  attemptCount: number;
  failureReason?: string | null;
  onRetry: () => void;
}) {
  const tooMany = attemptCount > 2;
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [needCreds, setNeedCreds] = useState(false);
  const [user, setUser] = useState('');
  const [pass, setPass] = useState('');
  const [refundDone, setRefundDone] = useState(false);
  const [refundReason, setRefundReason] = useState('');

  async function retry() {
    setBusy(true); setErr(null);
    try {
      await api.retryScan(orderId, needCreds ? { username: user.trim(), password: pass } : undefined);
      onRetry();
    } catch (e: any) {
      if (e?.needsCredentials) { setNeedCreds(true); setErr('Bu paket kimlik-doğrulamalı test içerir; devam etmek için test hesabı bilgilerini girin.'); }
      else setErr(e?.message ?? 'Tekrar denenemedi.');
    } finally { setBusy(false); }
  }

  async function requestRefund() {
    setBusy(true); setErr(null);
    try {
      await api.requestRefund(orderId, refundReason.trim() || undefined);
      setRefundDone(true);
    } catch (e: any) { setErr(e?.message ?? 'İade talebi gönderilemedi.'); }
    finally { setBusy(false); }
  }

  if (refundDone) {
    return (
      <div className="mt-6 rounded-card border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">
        <strong>İade talebiniz alındı.</strong> Ekibimiz talebinizi inceleyip en kısa sürede sizinle iletişime geçecek ve iadenizi işleme alacaktır.
      </div>
    );
  }

  return (
    <div className="mt-6 rounded-card border border-red-200 bg-red-50 px-4 py-4 text-sm text-red-800">
      <p className="font-semibold">Tarama tamamlanamadı</p>
      <p className="mt-1 text-red-700">{failureMessage(failureReason)}</p>

      {!tooMany ? (
        <>
          {needCreds && (
            <div className="mt-3 grid gap-2 sm:grid-cols-2">
              <input className="field" placeholder="Test hesabı kullanıcı adı" value={user} onChange={(e) => setUser(e.target.value)} autoComplete="off" />
              <input className="field" type="password" placeholder="Test hesabı şifresi" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="new-password" />
            </div>
          )}
          {err && <p className="mt-2 text-xs font-semibold text-red-700">{err}</p>}
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <button
              onClick={retry}
              disabled={busy || (needCreds && (!user.trim() || !pass))}
              className="btn-primary disabled:opacity-60"
            >
              {busy ? 'Deneniyor…' : 'Tekrar Dene'}
            </button>
            <button onClick={requestRefund} disabled={busy} className="text-xs font-medium text-red-700 underline">
              Bunun yerine iade talebinde bulun
            </button>
          </div>
        </>
      ) : (
        <>
          <p className="mt-2 text-xs text-red-700">Bu tarama birden çok kez denendi. Dilerseniz iade talebinde bulunabilirsiniz; ekibimiz işleme alacaktır.</p>
          <textarea className="field mt-2 min-h-[60px] w-full" placeholder="İade sebebiniz (opsiyonel)" value={refundReason} onChange={(e) => setRefundReason(e.target.value)} />
          {err && <p className="mt-2 text-xs font-semibold text-red-700">{err}</p>}
          <button onClick={requestRefund} disabled={busy} className="btn-primary mt-2 disabled:opacity-60">
            {busy ? 'Gönderiliyor…' : 'İade talebinde bulun'}
          </button>
        </>
      )}
    </div>
  );
}
