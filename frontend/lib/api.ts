import { readRegionCookie } from './region';
import { getRegion } from '../config/regions';

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

// (Çok-bölge) API katmanı React dışı — dili region cookie'sinden türetir. Ağ/oturum/limit gibi
// kod-tarafı hata mesajları böylece /de /en'de de doğru dilde çıkar (ham "Load failed" gösterilmez).
function apiLang(): 'tr' | 'de' | 'en' {
  const l = getRegion(readRegionCookie()).lang;
  return l === 'de' ? 'de' : l === 'en' ? 'en' : 'tr';
}
const MSG = {
  network: {
    tr: 'Sunucuya ulaşılamadı. İnternet bağlantınızı kontrol edip tekrar deneyin.',
    de: 'Server nicht erreichbar. Bitte prüfen Sie Ihre Internetverbindung und versuchen Sie es erneut.',
    en: 'Could not reach the server. Please check your internet connection and try again.',
  },
  timeout: {
    tr: 'İstek zaman aşımına uğradı. Bağlantınız yavaş olabilir; lütfen tekrar deneyin.',
    de: 'Zeitüberschreitung der Anfrage. Ihre Verbindung ist möglicherweise langsam; bitte versuchen Sie es erneut.',
    en: 'The request timed out. Your connection may be slow; please try again.',
  },
  expired: {
    tr: 'Oturumunuz sona ermiş görünüyor. Lütfen tekrar giriş yapın.',
    de: 'Ihre Sitzung ist offenbar abgelaufen. Bitte melden Sie sich erneut an.',
    en: 'Your session appears to have expired. Please sign in again.',
  },
  tooMany: {
    tr: 'Çok fazla deneme yapıldı. Lütfen biraz bekleyip tekrar deneyin.',
    de: 'Zu viele Versuche. Bitte warten Sie einen Moment und versuchen Sie es erneut.',
    en: 'Too many attempts. Please wait a moment and try again.',
  },
  generic: {
    tr: 'İşlem şu an tamamlanamadı. Lütfen bilgileri kontrol edip tekrar deneyin.',
    de: 'Die Aktion konnte derzeit nicht abgeschlossen werden. Bitte prüfen Sie die Angaben und versuchen Sie es erneut.',
    en: 'The action could not be completed right now. Please check your details and try again.',
  },
} as const;

// (ÜCRETSİZ ANLIK ÖN-TARAMA) sonuç tipi — üç-durum + skor + ≤3 bulgu başlığı.
export type InstantFinding = { title: string; severity: 'high' | 'medium' | 'low' };
export type InstantScanResult =
  | { host: string; status: 'unreachable' }
  | { host: string; status: 'access_error'; httpStatus: number }
  | {
      host: string;
      status: 'ok';
      score: number;
      grade: 'A' | 'B' | 'C' | 'D' | 'E' | 'F';
      total: number;
      shown: InstantFinding[];
      locked: number;
      lockedCats?: { ssl: number; header: number };
      clean: boolean;
      httpsOk: boolean;
      logId?: string;
    };

function authHeaders(): Record<string, string> {
  if (typeof window === 'undefined') return {};
  const token = window.localStorage.getItem('token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

// (OTONOM AI RED TEAM — beta kapısı) Sunucu-imzalı beta grant token'ı (kod DEĞİL) yerelde saklanır;
// beta uçlarında X-Beta-Token başlığı ile gider. Backend her istekte imzayı doğrular.
export const BETA_TOKEN_KEY = 'rt_beta';
function betaHeaders(): Record<string, string> {
  if (typeof window === 'undefined') return {};
  const t = window.localStorage.getItem(BETA_TOKEN_KEY);
  return t ? { 'X-Beta-Token': t } : {};
}

// API hatasını her zaman TEMİZ, kullanıcı-dostu bir cümleye indirger — ham Zod objesini
// ({fieldErrors,formErrors}) veya "[object Object]" ASLA gösterme (savunma katmanı; asıl temiz
// mesaj backend httpErrors.zodError'dan gelir).
function friendlyError(body: any, status: number): string {
  const e = body?.error;
  if (typeof e === 'string' && e.trim()) return e;
  if (e && typeof e === 'object') {
    const fe = (e as any).fieldErrors;
    if (fe && typeof fe === 'object') {
      for (const v of Object.values(fe)) if (Array.isArray(v) && v[0]) return String(v[0]);
    }
    if (Array.isArray((e as any).formErrors) && (e as any).formErrors[0]) return String((e as any).formErrors[0]);
  }
  if (typeof body?.message === 'string' && body.message.trim()) return body.message;
  const lang = apiLang();
  if (status === 401) return MSG.expired[lang];
  if (status === 429) return MSG.tooMany[lang];
  return MSG.generic[lang];
}

async function request<T>(path: string, options: RequestInit & { timeoutMs?: number } = {}): Promise<T> {
  // (HIZ) Opsiyonel istemci-tarafı zaman aşımı — uzun süren istekte UI takılı kalmasın (ör. ön-giriş).
  const { timeoutMs, ...init } = options;
  const ctrl = timeoutMs ? new AbortController() : null;
  const timer = ctrl ? setTimeout(() => ctrl.abort(), timeoutMs) : null;
  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, {
      ...init,
      signal: ctrl?.signal,
      headers: {
        'Content-Type': 'application/json',
        // (ÇOK-DİLLİ) Backend hata mesajları doğru dilde dönsün. GET uçlarının gövdesi olmadığından
        // sunucu dili gövdeden okuyamıyordu (hep 'tr'ye düşüyordu) → bölgeyi başlıkla gönderiyoruz.
        'X-Region': apiLang(),
        ...authHeaders(),
        ...init.headers,
      },
    });
  } catch (e: any) {
    // (AĞ HATASI) fetch'in KENDİSİ throw etti: bağlantı yok/kesildi (Safari "Load failed", Chrome
    // "Failed to fetch") ya da zaman aşımı (AbortError). Ham tarayıcı metnini GÖSTERME → bölgeye göre
    // dostça, anlaşılır mesaj. (HTTP hata YANITLARI aşağıda ayrıca friendlyError ile ele alınır.)
    const lang = apiLang();
    const isTimeout = e?.name === 'AbortError';
    const err = new Error(isTimeout ? MSG.timeout[lang] : MSG.network[lang]) as Error & { networkError?: boolean };
    err.networkError = true;
    throw err;
  } finally {
    if (timer) clearTimeout(timer);
  }
  if (!res.ok) {
    // (OTURUM TEMİZLİĞİ) 401 = token geçersiz/süresi dolmuş → localStorage'daki ölü token'ı SİL ki
    // Nav "giriş yapılmış" sanıp her istekte "geçersiz/süresi dolmuş oturum" döngüsüne girmesin.
    // Login/register 401'i (yanlış şifre) hariç — orada zaten token yok.
    if (res.status === 401 && typeof window !== 'undefined' && !path.startsWith('/auth/login') && !path.startsWith('/auth/register')) {
      const hadToken = !!window.localStorage.getItem('token');
      window.localStorage.removeItem('token');
      // (OTURUM BİTTİ — UX) Gerçekten oturumu VARDI da düştüyse: login'de düzgün, çok-dilli bir
      // bildirim gösterebilmek + kullanıcıyı kaldığı sayfaya geri döndürebilmek için işaretle.
      if (hadToken) {
        try {
          window.sessionStorage.setItem('sess_expired', '1');
          const loc = window.location.pathname + window.location.search;
          if (!/\/(login|register)/.test(loc)) window.sessionStorage.setItem('sess_return', loc);
        } catch { /* noop */ }
      }
    }
    const body = await res.json().catch(() => ({}));
    const msg = friendlyError(body, res.status);
    const err = new Error(msg) as Error & { status?: number; emailUnverified?: boolean; needsCredentials?: boolean; tooManyAttempts?: boolean };
    err.status = res.status;
    if (body.emailUnverified) err.emailUnverified = true;   // (satin alma) e-posta dogrulama gerekli
    if (body.needsCredentials) err.needsCredentials = true; // (retry) kimlik-dogrulamali paket kimlik ister
    if (body.tooManyAttempts) err.tooManyAttempts = true;   // (retry) cok deneme -> iade talebi
    throw err;
  }
  return res.json();
}

export const api = {
  register: (email: string, password: string, termsAccepted: boolean, turnstileToken?: string) =>
    request<{ token: string; emailVerified?: boolean; autoLogin?: boolean }>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, termsAccepted, turnstileToken, region: readRegionCookie() }),
    }),
  login: (email: string, password: string) =>
    request<{ token?: string; twofaRequired?: boolean; stageToken?: string }>('/auth/login', { method: 'POST', body: JSON.stringify({ email, password, region: readRegionCookie() }) }),
  // (2FA — OPT-IN) login 2. adımı + hesap ayarları + nudge. region → hata mesajı dili.
  login2fa: (stageToken: string, code: string) =>
    request<{ token: string }>('/twofa/login-verify', { method: 'POST', body: JSON.stringify({ stageToken, code, region: readRegionCookie() }) }),
  twofaStatus: () => request<{ enabled: boolean; remainingRecoveryCodes: number }>('/twofa/status'),
  twofaSetup: () => request<{ otpauthUri: string; qrDataUrl: string; manualKey: string }>('/twofa/setup', { method: 'POST', body: JSON.stringify({ region: readRegionCookie() }) }),
  twofaEnable: (code: string) => request<{ enabled: boolean; recoveryCodes: string[] }>('/twofa/enable', { method: 'POST', body: JSON.stringify({ code, region: readRegionCookie() }) }),
  twofaDisable: (code: string) => request<{ enabled: boolean }>('/twofa/disable', { method: 'POST', body: JSON.stringify({ code, region: readRegionCookie() }) }),
  twofaNudge: () => request<{ show: boolean }>('/twofa/nudge'),
  twofaNudgeDismiss: () => request<{ ok: boolean }>('/twofa/nudge/dismiss', { method: 'POST' }),
  twofaNudgeRemind: () => request<{ ok: boolean }>('/twofa/nudge/remind', { method: 'POST' }),
  // (ÜCRETSİZ ANLIK ÖN-TARAMA) public, pasif teaser. turnstileToken = bot doğrulaması; website = honeypot.
  instantScan: (url: string, turnstileToken?: string, website?: string, region?: string) =>
    request<InstantScanResult>('/instant-scan', { method: 'POST', body: JSON.stringify({ url, turnstileToken, website, region }) }),
  // (ANA SAYFA LEAD) e-posta + host → GERÇEK Basit Tarama raporu PDF blob'u. Ödeme/kayıt/admin-onayı YOK.
  instantScanReport: async (body: { logId?: string; url: string; email: string; region?: string }): Promise<Blob> => {
    const res = await fetch(`${API_URL}/instant-scan/report`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!res.ok) { const b = await res.json().catch(() => ({})); throw new Error((b && b.error) || 'Rapor alınamadı.'); }
    return res.blob();
  },
  // (0) E-posta dogrulama
  me: () => request<{ email: string; emailVerified: boolean }>('/auth/me'),
  verifyEmail: (code: string) =>
    request<{ ok: boolean; emailVerified: boolean }>('/auth/verify-email', { method: 'POST', body: JSON.stringify({ code, region: readRegionCookie() }) }),
  resendVerification: () => request<{ ok: boolean }>('/auth/resend-verification', { method: 'POST' }),
  // (A) Sifre sifirlama — forgot HER ZAMAN {ok:true} (enumeration korumasi); reset yeni token doner.
  forgotPassword: (email: string) =>
    request<{ ok: boolean }>('/auth/forgot-password', { method: 'POST', body: JSON.stringify({ email, region: readRegionCookie() }) }),
  resetPassword: (token: string, password: string) =>
    request<{ ok: boolean; token: string }>('/auth/reset-password', { method: 'POST', body: JSON.stringify({ token, password, region: readRegionCookie() }) }),
  createDomain: (hostname: string) =>
    request<{ domainId: string; hostname: string; alreadyVerified?: boolean; message?: string; instructions?: { recordName: string; recordValue: string; note: string } }>(
      '/domains',
      { method: 'POST', body: JSON.stringify({ hostname, region: readRegionCookie() }) },
    ),
  verifyDomain: (domainId: string) =>
    request<{ verified: boolean }>(`/domains/${domainId}/verify`, { method: 'POST', body: JSON.stringify({ region: readRegionCookie() }) }),
  deleteDomain: (domainId: string) =>
    request<{ ok: boolean }>(`/domains/${domainId}`, { method: 'DELETE' }),
  deleteAllDomains: () =>
    request<{ ok: boolean; deleted: number; kept: number }>('/domains', { method: 'DELETE' }),
  listDomains: () =>
    request<
      Array<{
        id: string;
        hostname: string;
        status: string;
        verifiedAt: string | null;
        valid: boolean;
        instructions: { recordName: string; recordValue: string };
      }>
    >('/domains'),
  listPackages: (region = 'tr') =>
    request<Array<{ key: string; displayName: string; description: string; priceMinorUnit: number; currency?: string; comingSoon?: boolean }>>(
      `/orders/packages?region=${region}`,
    ),
  createOrder: (
    domainId: string,
    packageKey: string,
    consents: { ownershipConfirmed: boolean; distanceContractAccepted: boolean; withdrawalWaived: boolean; crossBorderTransfer: boolean },
    region = 'tr',
    activeTestConsent?: { riskAccepted: boolean },
    authCredentials?: { username: string; password: string },
    promoCode?: string,
  ) =>
    request<{ orderId: string; paymentPageUrl?: string; paidWithPromo?: boolean }>('/orders', {
      method: 'POST',
      body: JSON.stringify({ domainId, packageKey, ...consents, region, activeTestConsent, authCredentials, promoCode }),
    }),
  // 'awaiting_payment' bir siparis icin GERCEK odeme sayfasini yeniden baslat (dashboard "Odemeyi Tamamla").
  resumePayment: (orderId: string) =>
    request<{ orderId: string; paymentPageUrl?: string; conversationId?: string }>(`/orders/${orderId}/pay`, {
      method: 'POST',
    }),
  // Kombine paketler (bundle) — bolgesel fiyat + uye listesi.
  listBundles: (region = 'tr') =>
    request<
      Array<{
        key: string; displayName: string; description: string; discountPct: number;
        selectable: boolean; selectableModules: Array<{ key: string; displayName: string }> | null;
        members: Array<{ key: string; displayName: string }>;
        originalMinorUnit: number; amountMinorUnit: number; currency: string; comingSoon?: boolean;
      }>
    >(`/orders/bundles?region=${region}`),
  // (Aktif Doğrulama Paketi) Ödeme öncesi hızlı kapsam tahmini — düşük sinyalde UI uyarı gösterir.
  scopeEstimate: (domainId: string) =>
    request<{ lowSignal: boolean; jsRendered: boolean; inputCount: number; reachable: boolean }>(
      `/domains/${domainId}/scope-estimate`,
    ),
  // (OTONOM AI RED TEAM — 3b) Beta kodunu SUNUCUDA doğrula; başarılıysa imzalı grant token döner.
  betaUnlock: (code: string) =>
    request<{ ok: boolean; betaToken: string; expiresInDays: number }>('/beta/unlock', {
      method: 'POST',
      body: JSON.stringify({ code }),
    }),
  // Pasif kompleksite → fiyat bandı ÖNERİSİ (PentAGI yok, ekstra tarama yok). Grant token gerekli.
  betaEstimate: (domain: string) =>
    request<{
      host: string;
      signals: { uniqueEndpoints: number; realApiEndpoints: number; authSurface: boolean; subdomains: number; techDiversity: number } | null;
      suggestion: {
        score: number;
        tier: { key: string; label: string };
        priceRange: { minTL: number | null; maxTL: number | null; placeholder: boolean };
        note: string;
      } | null;
      note?: string;
    }>('/beta/estimate', { method: 'POST', headers: betaHeaders(), body: JSON.stringify({ domain }), timeoutMs: 30_000 }),
  // (S1) Karmaşıklık-bazlı NET fiyat (ödeme öncesi). PentAGI/droplet çalışmaz — ucuz pasif ön-kontrol.
  betaS1Price: (domain: string) =>
    request<{
      host: string; level: 'S1'; currency: string; priceTL: number;
      tier: { key: string; label: string; desc: string }; reason: string; estEndpoints: number; note: string;
    }>('/beta/s1-price', { method: 'POST', headers: betaHeaders(), body: JSON.stringify({ domain }), timeoutMs: 30_000 }),
  // 3b-i STUB: gerçek koşu YOK. Sahiplik/onay sunucuda doğrulanır; "Hazırlanıyor" döner.
  betaStart: (payload: {
    domain: string;
    level: 'S1' | 'S2' | 'S3';
    environment: 'test' | 'staging' | 'prod';
    ownershipConfirmed: boolean;
    riskAccepted: boolean;
    prodElevatedAccepted?: boolean;
  }) =>
    request<{ status: string; started: boolean; message: string }>('/beta/start', {
      method: 'POST',
      headers: betaHeaders(),
      body: JSON.stringify(payload),
    }),
  // (ÖDEME ÖNCESİ TEST GİRİŞİ) kendi doğrulanmış domainine test hesabıyla 1 login dener; saklamaz.
  precheckLogin: (domainId: string, username: string, password: string) =>
    request<{ ok: boolean; reason?: 'bad_credentials' | 'two_factor' | 'no_login_endpoint' | 'timeout' | 'error' }>(
      '/orders/precheck-login',
      { method: 'POST', body: JSON.stringify({ domainId, username, password }), timeoutMs: 32_000 },
    ),
  createBundleOrder: (body: {
    domainId: string; bundleKey: string; selectedModules?: string[];
    ownershipConfirmed: boolean; distanceContractAccepted: boolean; withdrawalWaived: boolean; crossBorderTransfer: boolean;
    region?: string; activeTestConsent?: { riskAccepted: boolean };
    authCredentials?: { username: string; password: string }; promoCode?: string; lowScopeAcknowledged?: boolean;
  }) =>
    request<{ bundleKey: string; orderIds: string[]; paidWithPromo?: boolean; paymentPending?: boolean; bundleTotalMinorUnit?: number; currency?: string; paymentPageUrl?: string; conversationId?: string }>(
      '/orders/bundle',
      { method: 'POST', body: JSON.stringify(body) },
    ),
  // Promo kodu onizleme — tekil paket (packageKey) VEYA kombine paket (bundleKey) icin.
  previewPromo: (code: string, target: { packageKey?: string; bundleKey?: string }, region = 'tr') =>
    request<{
      valid: boolean; error?: string; code?: string;
      discountType?: 'percentage' | 'fixed'; discountValue?: number;
      originalAmountMinorUnit?: number; discountMinorUnit?: number; finalAmountMinorUnit?: number; currency?: string;
    }>('/orders/promo/preview', { method: 'POST', body: JSON.stringify({ code, ...target, region }) }),
  // Aktif basit_tarama promo kodu (varsa) — checkout'ta Basit Tarama seçiliyken kampanya bloğu için.
  activeBasitPromo: () => request<{ promo: { code: string } | null }>('/promo/active-basit'),
  // (Fatura talebi — MANUEL) ödemesi tamamlanmış sipariş için fatura bilgisi gönder/güncelle.
  requestInvoice: (orderId: string, body: {
    type: 'bireysel' | 'kurumsal';
    companyName?: string; taxOffice?: string; taxNumber?: string;
    fullName?: string; nationalId?: string;
    address: string; invoiceEmail: string;
  }) =>
    request<{ ok: boolean; updated?: boolean }>(`/orders/${orderId}/invoice-request`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  // (Başarısız tarama) Tekrar dene — kimlik-doğrulamalı pakette yeni test hesabı bilgisi gerekebilir.
  retryScan: (orderId: string, opts?: { username: string; password: string } | { loginless: true }) =>
    request<{ ok: boolean; attempt?: number }>(`/orders/${orderId}/retry`, {
      method: 'POST',
      body: JSON.stringify(
        opts && 'loginless' in opts ? { loginless: true }
        : opts ? { authCredentials: opts }
        : {},
      ),
    }),
  // (Başarısız/iptal) İade talebi — admin panelde görünür, ekip iyzico'dan manuel iade yapar.
  requestRefund: (orderId: string, reason?: string) =>
    request<{ ok: boolean; alreadyRequested?: boolean }>(`/orders/${orderId}/refund-request`, {
      method: 'POST',
      body: JSON.stringify(reason ? { reason } : {}),
    }),
  getOrder: (orderId: string) => request<any>(`/orders/${orderId}`),
  // (#4) Kuyruk yogunlugu — yeni siparis oncesi "yogunuz" uyarisi icin.
  getQueueStatus: () =>
    request<{ queuedCount: number; running: boolean; avgScanMinutes: number; etaMinutes: number; threshold: number; busy: boolean }>(
      '/orders/queue/status',
    ),
  listOrders: (archived = false) =>
    request<
      Array<{ id: string; hostname: string; packageName: string; status: string; createdAt: string; archived: boolean }>
    >(`/orders${archived ? '?archived=true' : ''}`),
  archiveOrder: (orderId: string, archived: boolean) =>
    request<{ ok: boolean; archived: boolean }>(`/orders/${orderId}/archive`, {
      method: 'PATCH',
      body: JSON.stringify({ archived }),
    }),
  deleteOrder: (orderId: string) => request<{ ok: boolean }>(`/orders/${orderId}`, { method: 'DELETE' }),
  listSchedules: () =>
    request<
      Array<{
        id: string;
        hostname: string;
        packageKey: string;
        intervalDays: number;
        remainingRuns: number;
        nextRunAt: string;
        active: boolean;
      }>
    >('/schedules'),
  createSchedule: (body: {
    domainId: string;
    packageKey: string;
    intervalDays: number;
    runs: number;
    startAt?: string; // ISO — ileri tarihli ilk calisma (yoksa hemen)
    region: string;
  }) => request<{ id: string }>('/schedules', { method: 'POST', body: JSON.stringify(body) }),
  cancelSchedule: (id: string) => request<{ ok: boolean }>(`/schedules/${id}`, { method: 'DELETE' }),
  // (UX) Erişim kodunu TEKRAR GÖNDER — AYNI kod hesabın e-postasına yeniden yollanır
  // (kod raporun şifreleme anahtarı olduğu için yenilenmez; güvenlik modeli değişmedi).
  resendReportCode: (orderId: string) =>
    request<{ ok: boolean }>(`/reports/${orderId}/resend-code`, { method: 'POST', body: JSON.stringify({ region: readRegionCookie() }) }),
  downloadReport: async (orderId: string, accessSecret: string) => {
    const res = await fetch(`${API_URL}/reports/${orderId}/download`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ accessSecret }),
    });
    if (!res.ok) throw new Error(
      readRegionCookie() === 'de'
        ? 'Bericht konnte nicht heruntergeladen werden. Bitte prüfen Sie das Zugriffspasswort.'
        : 'Rapor indirilemedi. Erişim şifresini kontrol edin.',
    );
    return res.blob();
  },
  // (3) AI Cozum Onerileri eklentisi: satin al (unlock) + indir.
  // promoCode verilirse indirim; %100 -> dogrudan acilir (unlockedAt), aksi halde iyzico paymentPageUrl doner.
  unlockFixSuggestions: (orderId: string, promoCode?: string) =>
    request<{ ok?: boolean; unlockedAt?: string; paymentPageUrl?: string }>(`/reports/${orderId}/fix-suggestions/unlock`, {
      method: 'POST',
      body: JSON.stringify(promoCode ? { promoCode } : {}),
    }),
  downloadFixSuggestions: async (orderId: string, accessSecret: string) => {
    const res = await fetch(`${API_URL}/reports/${orderId}/fix-suggestions/download`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ accessSecret }),
    });
    if (!res.ok) throw new Error(
      readRegionCookie() === 'de'
        ? 'Lösungsvorschläge konnten nicht heruntergeladen werden. Bitte prüfen Sie das Zugriffspasswort/den Freischaltstatus.'
        : 'Çözüm önerileri indirilemedi. Erişim şifresini/kilit durumunu kontrol edin.',
    );
    return res.blob();
  },
};
