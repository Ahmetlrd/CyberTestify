'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { adminApi, ADMIN_TOKEN_KEY } from '../../../lib/adminApi';
import { OtpInput } from '../../../components/OtpInput';

type Step = 'pw' | 'verify' | 'enroll' | 'recovery';

export default function AdminLogin() {
  const router = useRouter();
  const [step, setStep] = useState<Step>('pw');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [stageToken, setStageToken] = useState('');
  const [code, setCode] = useState('');
  const [setup, setSetup] = useState<{ qrDataUrl: string; manualKey: string } | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [copied, setCopied] = useState('');
  const [useRecovery, setUseRecovery] = useState(false); // verify adımında kurtarma kodu girişi
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function finish(token: string) {
    window.localStorage.setItem(ADMIN_TOKEN_KEY, token);
    router.replace('/admin/dashboard');
  }
  const copy = (txt: string, what: string) => { navigator.clipboard?.writeText(txt).then(() => { setCopied(what); setTimeout(() => setCopied(''), 1500); }); };

  async function submitPw(e: React.FormEvent) {
    e.preventDefault(); setBusy(true); setError(null);
    try {
      const r = await adminApi.login(email.trim().toLowerCase(), password);
      if (r.token) return finish(r.token);
      if (r.twofaRequired && r.stageToken) { setStageToken(r.stageToken); setStep('verify'); }
      else if (r.enrollmentRequired && r.stageToken) {
        setStageToken(r.stageToken);
        const s = await adminApi.twofaSetup(r.stageToken);
        setSetup({ qrDataUrl: s.qrDataUrl, manualKey: s.manualKey }); setStep('enroll');
      } else setError('Beklenmeyen yanıt.');
    } catch (err: any) { setError(err.message || 'Giriş başarısız.'); }
    setBusy(false);
  }

  async function submitVerify(e: React.FormEvent) {
    e.preventDefault(); setBusy(true); setError(null);
    try { const { token } = await adminApi.login2fa(stageToken, code.trim()); finish(token); }
    catch (err: any) { setError(err.message || 'Kod doğrulanamadı.'); setBusy(false); }
  }

  async function submitEnroll(e: React.FormEvent) {
    e.preventDefault(); setBusy(true); setError(null);
    try {
      const r = await adminApi.twofaEnable(stageToken, code.trim());
      window.localStorage.setItem(ADMIN_TOKEN_KEY, r.token); // tam oturum hazır
      setRecoveryCodes(r.recoveryCodes); setCode(''); setStep('recovery');
    } catch (err: any) { setError(err.message || 'Etkinleştirme başarısız.'); }
    setBusy(false);
  }

  const input: React.CSSProperties = { width: '100%', padding: '10px 12px', borderRadius: 8, border: '1px solid #334155', background: '#0f172a', color: '#e2e8f0', fontSize: 14, marginTop: 6 };
  const codeInput: React.CSSProperties = { ...input, letterSpacing: '0.4em', textAlign: 'center', fontSize: 20, fontFamily: 'ui-monospace, monospace' };
  const btn: React.CSSProperties = { width: '100%', marginTop: 20, padding: '10px', borderRadius: 8, border: 'none', background: '#38bdf8', color: '#0f172a', fontWeight: 700, fontSize: 14, cursor: 'pointer' };
  const small = { fontSize: 12, color: '#94a3b8' } as React.CSSProperties;

  return (
    <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', background: '#0f172a', fontFamily: 'ui-sans-serif, system-ui, sans-serif', padding: 20 }}>
      <div style={{ width: 380, background: '#1e293b', border: '1px solid #334155', borderRadius: 12, padding: 28, color: '#e2e8f0' }}>
        <h1 style={{ fontSize: 18, fontWeight: 700, color: '#fff', margin: '0 0 4px' }}>CyberTestify · Admin</h1>

        {step === 'pw' && (
          <form onSubmit={submitPw}>
            <p style={{ ...small, margin: '0 0 20px' }}>İç yönetim paneli — yalnızca yetkili erişim. Giriş iki faktörlü (2FA) doğrulama gerektirir.</p>
            <label style={{ fontSize: 13, color: '#cbd5e1' }}>E-posta
              <input style={input} type="email" required value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" />
            </label>
            <label style={{ fontSize: 13, color: '#cbd5e1', display: 'block', marginTop: 14 }}>Şifre
              <input style={input} type="password" required value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
            </label>
            {error && <p style={{ color: '#fca5a5', fontSize: 13, marginTop: 14 }}>{error}</p>}
            <button type="submit" disabled={busy} style={{ ...btn, opacity: busy ? 0.6 : 1 }}>{busy ? 'Giriş yapılıyor…' : 'Devam et'}</button>
          </form>
        )}

        {step === 'verify' && (
          <form onSubmit={submitVerify}>
            <p style={{ ...small, margin: '0 0 16px' }}>{useRecovery ? <>Bir <b>kurtarma kodunuzu</b> girin.</> : <>Authenticator uygulamanızdaki <b>6 haneli kodu</b> girin.</>}</p>
            {useRecovery ? (
              <input style={codeInput} inputMode="text" autoFocus placeholder="xxxxx-xxxxx" value={code} onChange={(e) => setCode(e.target.value)} />
            ) : (
              <OtpInput value={code} onChange={setCode} theme="dark" autoFocus />
            )}
            {error && <p style={{ color: '#fca5a5', fontSize: 13, marginTop: 14 }}>{error}</p>}
            <button type="submit" disabled={busy || (!useRecovery && code.length !== 6)} style={{ ...btn, opacity: busy || (!useRecovery && code.length !== 6) ? 0.6 : 1 }}>{busy ? 'Doğrulanıyor…' : 'Doğrula ve gir'}</button>
            <button type="button" onClick={() => { setUseRecovery(!useRecovery); setCode(''); setError(null); }} style={{ width: '100%', marginTop: 12, background: 'none', border: 'none', color: '#94a3b8', fontSize: 12, cursor: 'pointer' }}>
              {useRecovery ? '← Authenticator kodu kullan' : 'Telefonum yok — kurtarma kodu gir'}
            </button>
          </form>
        )}

        {step === 'enroll' && setup && (
          <form onSubmit={submitEnroll}>
            <p style={{ ...small, margin: '0 0 12px' }}>Admin girişi için 2FA kurulumu <b>zorunludur</b>. Authenticator uygulamanızla (Google Authenticator, Authy, 1Password…) QR'ı okutun:</p>
            <div style={{ textAlign: 'center', margin: '8px 0' }}>
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img src={setup.qrDataUrl} alt="2FA QR" width={200} height={200} style={{ borderRadius: 8, background: '#fff', padding: 6 }} />
            </div>
            <div style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8, padding: '10px 12px', marginTop: 6 }}>
              <div style={small}>QR okutamıyorsanız (mobil), authenticator'da <b>"Kurulum anahtarı gir"</b> ile bu anahtarı elle girin:</div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 8 }}>
                <code style={{ flex: 1, fontSize: 13, color: '#e2e8f0', wordBreak: 'break-all', fontFamily: 'ui-monospace, monospace' }}>{setup.manualKey}</code>
                <button type="button" onClick={() => copy(setup.manualKey, 'key')} style={{ padding: '6px 10px', borderRadius: 6, border: '1px solid #334155', background: '#334155', color: '#e2e8f0', fontSize: 12, cursor: 'pointer', whiteSpace: 'nowrap' }}>{copied === 'key' ? 'Kopyalandı ✓' : 'Kopyala'}</button>
              </div>
            </div>
            <div style={{ fontSize: 13, color: '#cbd5e1', marginTop: 16, marginBottom: 8 }}>Uygulamadaki 6 haneli kodu girin</div>
            <OtpInput value={code} onChange={setCode} theme="dark" />
            {error && <p style={{ color: '#fca5a5', fontSize: 13, marginTop: 14 }}>{error}</p>}
            <button type="submit" disabled={busy || code.length !== 6} style={{ ...btn, opacity: busy || code.length !== 6 ? 0.6 : 1 }}>{busy ? 'Etkinleştiriliyor…' : '2FA’yı etkinleştir'}</button>
          </form>
        )}

        {step === 'recovery' && (
          <div>
            <p style={{ fontSize: 13, color: '#cbd5e1', margin: '0 0 6px' }}>2FA etkinleştirildi. Aşağıdaki <b>kurtarma kodlarını</b> güvenli bir yere kaydedin — telefonunuzu kaybederseniz bunlarla giriş yapabilirsiniz. Her kod <b>bir kez</b> kullanılır ve bu ekran <b>tekrar gösterilmez</b>.</p>
            <div style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8, padding: 14, margin: '12px 0', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, fontFamily: 'ui-monospace, monospace', fontSize: 14, color: '#e2e8f0' }}>
              {recoveryCodes.map((c) => <div key={c}>{c}</div>)}
            </div>
            <button type="button" onClick={() => copy(recoveryCodes.join('\n'), 'rec')} style={{ width: '100%', padding: '8px', borderRadius: 8, border: '1px solid #334155', background: '#334155', color: '#e2e8f0', fontSize: 13, cursor: 'pointer' }}>{copied === 'rec' ? 'Kopyalandı ✓' : 'Tümünü kopyala'}</button>
            <button type="button" onClick={() => router.replace('/admin/dashboard')} style={{ ...btn }}>Kaydettim, panele geç</button>
          </div>
        )}
      </div>
    </div>
  );
}
