const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

// (ÜCRETSİZ ANLIK ÖN-TARAMA) sonuç tipi — üç-durum + skor + ≤3 bulgu başlığı.
export type InstantFinding = { title: string; severity: 'high' | 'medium' | 'low' };
export type InstantScanResult =
  | { host: string; status: 'unreachable' }
  | {
      host: string;
      status: 'ok';
      score: number;
      grade: 'A' | 'B' | 'C' | 'D' | 'E' | 'F';
      total: number;
      shown: InstantFinding[];
      locked: number;
      clean: boolean;
      httpsOk: boolean;
    };

function authHeaders(): Record<string, string> {
  if (typeof window === 'undefined') return {};
  const token = window.localStorage.getItem('token');
  return token ? { Authorization: `Bearer ${token}` } : {};
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
  if (status === 401) return 'Oturumunuz sona ermiş görünüyor. Lütfen tekrar giriş yapın.';
  if (status === 429) return 'Çok fazla deneme yapıldı. Lütfen biraz bekleyip tekrar deneyin.';
  return 'İşlem şu an tamamlanamadı. Lütfen bilgileri kontrol edip tekrar deneyin.';
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders(),
      ...options.headers,
    },
  });
  if (!res.ok) {
    // (OTURUM TEMİZLİĞİ) 401 = token geçersiz/süresi dolmuş → localStorage'daki ölü token'ı SİL ki
    // Nav "giriş yapılmış" sanıp her istekte "geçersiz/süresi dolmuş oturum" döngüsüne girmesin.
    // Login/register 401'i (yanlış şifre) hariç — orada zaten token yok.
    if (res.status === 401 && typeof window !== 'undefined' && !path.startsWith('/auth/login') && !path.startsWith('/auth/register')) {
      window.localStorage.removeItem('token');
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
      body: JSON.stringify({ email, password, termsAccepted, turnstileToken }),
    }),
  login: (email: string, password: string) =>
    request<{ token: string }>('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  // (ÜCRETSİZ ANLIK ÖN-TARAMA) public, pasif teaser. turnstileToken = bot doğrulaması; website = honeypot.
  instantScan: (url: string, turnstileToken?: string, website?: string) =>
    request<InstantScanResult>('/instant-scan', { method: 'POST', body: JSON.stringify({ url, turnstileToken, website }) }),
  // (0) E-posta dogrulama
  me: () => request<{ email: string; emailVerified: boolean }>('/auth/me'),
  verifyEmail: (code: string) =>
    request<{ ok: boolean; emailVerified: boolean }>('/auth/verify-email', { method: 'POST', body: JSON.stringify({ code }) }),
  resendVerification: () => request<{ ok: boolean }>('/auth/resend-verification', { method: 'POST' }),
  // (A) Sifre sifirlama — forgot HER ZAMAN {ok:true} (enumeration korumasi); reset yeni token doner.
  forgotPassword: (email: string) =>
    request<{ ok: boolean }>('/auth/forgot-password', { method: 'POST', body: JSON.stringify({ email }) }),
  resetPassword: (token: string, password: string) =>
    request<{ ok: boolean; token: string }>('/auth/reset-password', { method: 'POST', body: JSON.stringify({ token, password }) }),
  createDomain: (hostname: string) =>
    request<{ domainId: string; hostname: string; alreadyVerified?: boolean; message?: string; instructions?: { recordName: string; recordValue: string; note: string } }>(
      '/domains',
      { method: 'POST', body: JSON.stringify({ hostname }) },
    ),
  verifyDomain: (domainId: string) =>
    request<{ verified: boolean }>(`/domains/${domainId}/verify`, { method: 'POST' }),
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
  // (ÖDEME ÖNCESİ TEST GİRİŞİ) kendi doğrulanmış domainine test hesabıyla 1 login dener; saklamaz.
  precheckLogin: (domainId: string, username: string, password: string) =>
    request<{ ok: boolean; reason?: 'bad_credentials' | 'two_factor' | 'no_login_endpoint' | 'error' }>(
      '/orders/precheck-login',
      { method: 'POST', body: JSON.stringify({ domainId, username, password }) },
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
  retryScan: (orderId: string, authCredentials?: { username: string; password: string }) =>
    request<{ ok: boolean; attempt?: number }>(`/orders/${orderId}/retry`, {
      method: 'POST',
      body: JSON.stringify(authCredentials ? { authCredentials } : {}),
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
  downloadReport: async (orderId: string, accessSecret: string) => {
    const res = await fetch(`${API_URL}/reports/${orderId}/download`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ accessSecret }),
    });
    if (!res.ok) throw new Error('Rapor indirilemedi. Erişim şifresini kontrol edin.');
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
    if (!res.ok) throw new Error('Çözüm önerileri indirilemedi. Erişim şifresini/kilit durumunu kontrol edin.');
    return res.blob();
  },
};
