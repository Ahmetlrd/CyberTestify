'use client';

import { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { OtpInput } from './OtpInput';

// (2FA — müşteri hesap ayarları) Etkinleştir/kapat + QR + manuel anahtar + kurtarma kodları. tr/de/en.
const T2 = {
  tr: {
    title: 'İki Faktörlü Doğrulama (2FA)',
    desc: 'Raporlarınız gizlidir. Hesabınıza telefonunuzdaki authenticator uygulamasıyla ikinci bir doğrulama katmanı ekleyin. Ücretsiz.',
    on: 'Etkin', off: 'Kapalı', remaining: 'kurtarma kodu kaldı',
    enable: 'Etkinleştir', disable: 'Kapat', cancel: 'Vazgeç',
    scanHint: 'Authenticator uygulamanızla (Google Authenticator, Authy, 1Password…) QR’ı okutun:',
    manualHint: 'QR okutamıyorsanız (mobil), uygulamada “Kurulum anahtarı gir” ile bu anahtarı elle girin:',
    copy: 'Kopyala', copied: 'Kopyalandı ✓',
    codeLabel: 'Uygulamadaki 6 haneli kodu girin',
    activate: '2FA’yı etkinleştir', activating: 'Etkinleştiriliyor…',
    recTitle: 'Kurtarma kodlarınızı kaydedin',
    recDesc: 'Telefonunuzu kaybederseniz bu kodlarla giriş yapabilirsiniz. Her kod bir kez kullanılır ve bu liste tekrar gösterilmez.',
    copyAll: 'Tümünü kopyala', done: 'Kaydettim',
    disableHint: 'Kapatmak için mevcut 6 haneli kodunuzu girin:',
    confirmDisable: 'Kapat', disabling: 'Kapatılıyor…',
    recoveryUse: 'Kurtarma kodu kullan', recoveryBack: '← 6 haneli kod', recoveryHint: 'Bir kurtarma kodunuzu girin:',
  },
  de: {
    title: 'Zwei-Faktor-Authentifizierung (2FA)',
    desc: 'Ihre Berichte sind vertraulich. Fügen Sie Ihrem Konto mit einer Authenticator-App auf Ihrem Telefon eine zweite Sicherheitsebene hinzu. Kostenlos.',
    on: 'Aktiv', off: 'Deaktiviert', remaining: 'Wiederherstellungscodes übrig',
    enable: 'Aktivieren', disable: 'Deaktivieren', cancel: 'Abbrechen',
    scanHint: 'Scannen Sie den QR-Code mit Ihrer Authenticator-App (Google Authenticator, Authy, 1Password…):',
    manualHint: 'Wenn Sie den QR nicht scannen können (mobil), geben Sie diesen Schlüssel in der App über „Einrichtungsschlüssel eingeben“ manuell ein:',
    copy: 'Kopieren', copied: 'Kopiert ✓',
    codeLabel: 'Geben Sie den 6-stelligen Code aus der App ein',
    activate: '2FA aktivieren', activating: 'Wird aktiviert…',
    recTitle: 'Speichern Sie Ihre Wiederherstellungscodes',
    recDesc: 'Wenn Sie Ihr Telefon verlieren, können Sie sich mit diesen Codes anmelden. Jeder Code ist einmal verwendbar und diese Liste wird nicht erneut angezeigt.',
    copyAll: 'Alle kopieren', done: 'Gespeichert',
    disableHint: 'Zum Deaktivieren geben Sie Ihren aktuellen 6-stelligen Code ein:',
    confirmDisable: 'Deaktivieren', disabling: 'Wird deaktiviert…',
    recoveryUse: 'Wiederherstellungscode verwenden', recoveryBack: '← 6-stelliger Code', recoveryHint: 'Geben Sie einen Wiederherstellungscode ein:',
  },
  en: {
    title: 'Two-Factor Authentication (2FA)',
    desc: 'Your reports are confidential. Add a second layer of verification to your account with an authenticator app on your phone. Free.',
    on: 'Enabled', off: 'Disabled', remaining: 'recovery codes left',
    enable: 'Enable', disable: 'Disable', cancel: 'Cancel',
    scanHint: 'Scan the QR code with your authenticator app (Google Authenticator, Authy, 1Password…):',
    manualHint: 'If you can’t scan the QR (on mobile), enter this key manually in the app via “Enter a setup key”:',
    copy: 'Copy', copied: 'Copied ✓',
    codeLabel: 'Enter the 6-digit code from the app',
    activate: 'Enable 2FA', activating: 'Enabling…',
    recTitle: 'Save your recovery codes',
    recDesc: 'If you lose your phone, you can sign in with these codes. Each code is single-use and this list is not shown again.',
    copyAll: 'Copy all', done: 'Saved',
    disableHint: 'To disable, enter your current 6-digit code:',
    confirmDisable: 'Disable', disabling: 'Disabling…',
    recoveryUse: 'Use a recovery code', recoveryBack: '← 6-digit code', recoveryHint: 'Enter one of your recovery codes:',
  },
} as const;

type Mode = 'idle' | 'enrolling' | 'recovery' | 'disabling';

export function TwoFactorSection({ lang }: { lang: 'tr' | 'de' | 'en' }) {
  const t = T2[lang];
  const [status, setStatus] = useState<{ enabled: boolean; remainingRecoveryCodes: number } | null>(null);
  const [mode, setMode] = useState<Mode>('idle');
  const [setup, setSetup] = useState<{ qrDataUrl: string; manualKey: string } | null>(null);
  const [code, setCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [copied, setCopied] = useState('');
  const [useRecovery, setUseRecovery] = useState(false); // kapatmada kurtarma kodu girişi
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { api.twofaStatus().then(setStatus).catch(() => setStatus({ enabled: false, remainingRecoveryCodes: 0 })); }, []);
  const copy = (txt: string, what: string) => { navigator.clipboard?.writeText(txt).then(() => { setCopied(what); setTimeout(() => setCopied(''), 1500); }); };
  const reset = () => { setMode('idle'); setSetup(null); setCode(''); setError(null); setUseRecovery(false); };

  async function startEnroll() {
    setBusy(true); setError(null);
    try { const s = await api.twofaSetup(); setSetup({ qrDataUrl: s.qrDataUrl, manualKey: s.manualKey }); setMode('enrolling'); }
    catch (e: any) { setError(e.message); }
    setBusy(false);
  }
  async function confirmEnable() {
    setBusy(true); setError(null);
    try { const r = await api.twofaEnable(code.trim()); setRecoveryCodes(r.recoveryCodes); setCode(''); setMode('recovery'); }
    catch (e: any) { setError(e.message); }
    setBusy(false);
  }
  async function confirmDisable() {
    setBusy(true); setError(null);
    try { await api.twofaDisable(code.trim()); setStatus({ enabled: false, remainingRecoveryCodes: 0 }); reset(); }
    catch (e: any) { setError(e.message); }
    setBusy(false);
  }
  function finishRecovery() { setStatus({ enabled: true, remainingRecoveryCodes: recoveryCodes.length }); setRecoveryCodes([]); reset(); }


  return (
    <div className="rounded-card border border-line bg-white p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-base font-bold text-brand">{t.title}</h2>
          <p className="mt-1 text-xs text-ink-muted">{t.desc}</p>
        </div>
        {status && (
          <span className={`shrink-0 rounded-pill px-2.5 py-1 text-xs font-bold ${status.enabled ? 'bg-emerald-100 text-emerald-800' : 'bg-ink-soft/10 text-ink-soft'}`}>
            {status.enabled ? t.on : t.off}
          </span>
        )}
      </div>

      {status && !status.enabled && mode === 'idle' && (
        <button onClick={startEnroll} disabled={busy} className="btn-primary mt-4 w-full justify-center disabled:opacity-60">{t.enable}</button>
      )}

      {status?.enabled && mode === 'idle' && (
        <div className="mt-4">
          <p className="text-xs text-ink-muted">{status.remainingRecoveryCodes} {t.remaining}</p>
          <button onClick={() => { setMode('disabling'); setError(null); setCode(''); }} className="btn-outline mt-3 w-full justify-center">{t.disable}</button>
        </div>
      )}

      {mode === 'enrolling' && setup && (
        <div className="mt-4 space-y-3">
          <p className="text-xs text-ink-muted">{t.scanHint}</p>
          <div className="flex justify-center">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src={setup.qrDataUrl} alt="2FA QR" width={190} height={190} className="rounded-card border border-line bg-white p-2" />
          </div>
          <div className="rounded-card bg-brand-50/50 p-3">
            <p className="text-[11px] text-ink-muted">{t.manualHint}</p>
            <div className="mt-2 flex items-center gap-2">
              <code className="flex-1 break-all font-mono text-xs text-ink">{setup.manualKey}</code>
              <button type="button" onClick={() => copy(setup.manualKey, 'key')} className="shrink-0 rounded-pill border border-line px-2.5 py-1 text-xs font-semibold hover:bg-white">{copied === 'key' ? t.copied : t.copy}</button>
            </div>
          </div>
          <label className="label">{t.codeLabel}</label>
          <OtpInput value={code} onChange={setCode} />
          {error && <p className="form-error">{error}</p>}
          <div className="flex gap-2">
            <button onClick={reset} className="btn-outline flex-1 justify-center">{t.cancel}</button>
            <button onClick={confirmEnable} disabled={busy || code.length !== 6} className="btn-primary flex-1 justify-center disabled:opacity-60">{busy ? t.activating : t.activate}</button>
          </div>
        </div>
      )}

      {mode === 'recovery' && (
        <div className="mt-4 space-y-3">
          <p className="text-sm font-semibold text-emerald-800">✅ {t.recTitle}</p>
          <p className="text-xs text-ink-muted">{t.recDesc}</p>
          <div className="grid grid-cols-2 gap-1.5 rounded-card bg-brand-50/50 p-3 font-mono text-sm text-ink">
            {recoveryCodes.map((c) => <div key={c}>{c}</div>)}
          </div>
          <button type="button" onClick={() => copy(recoveryCodes.join('\n'), 'rec')} className="btn-outline w-full justify-center">{copied === 'rec' ? t.copied : t.copyAll}</button>
          <button onClick={finishRecovery} className="btn-primary w-full justify-center">{t.done}</button>
        </div>
      )}

      {mode === 'disabling' && (
        <div className="mt-4 space-y-3">
          <p className="text-xs text-ink-muted">{useRecovery ? t.recoveryHint : t.disableHint}</p>
          {useRecovery ? (
            <input inputMode="text" placeholder="xxxxx-xxxxx" value={code} onChange={(e) => setCode(e.target.value)}
              className="field text-center text-lg tracking-[0.2em]" style={{ fontFamily: 'ui-monospace, monospace' }} />
          ) : (
            <OtpInput value={code} onChange={setCode} />
          )}
          <button type="button" onClick={() => { setUseRecovery(!useRecovery); setCode(''); setError(null); }} className="w-full text-xs text-ink-muted hover:underline">
            {useRecovery ? t.recoveryBack : t.recoveryUse}
          </button>
          {error && <p className="form-error">{error}</p>}
          <div className="flex gap-2">
            <button onClick={reset} className="btn-outline flex-1 justify-center">{t.cancel}</button>
            <button onClick={confirmDisable} disabled={busy || code.trim().length < 6} className="flex-1 justify-center rounded-pill bg-red-600 px-4 py-2 text-sm font-bold text-white hover:bg-red-700 disabled:opacity-60">{busy ? t.disabling : t.confirmDisable}</button>
          </div>
        </div>
      )}
    </div>
  );
}
