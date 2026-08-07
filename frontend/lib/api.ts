const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

function authHeaders(): Record<string, string> {
  if (typeof window === 'undefined') return {};
  const token = window.localStorage.getItem('token');
  return token ? { Authorization: `Bearer ${token}` } : {};
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
    const body = await res.json().catch(() => ({}));
    const msg = typeof body.error === 'string' ? body.error : body.error ? JSON.stringify(body.error) : `İstek başarısız: ${res.status}`;
    const err = new Error(msg) as Error & { status?: number; emailUnverified?: boolean };
    err.status = res.status;
    if (body.emailUnverified) err.emailUnverified = true; // (satin alma) e-posta dogrulama gerekli
    throw err;
  }
  return res.json();
}

export const api = {
  register: (email: string, password: string, termsAccepted: boolean) =>
    request<{ token: string; emailVerified?: boolean; autoLogin?: boolean }>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, termsAccepted }),
    }),
  login: (email: string, password: string) =>
    request<{ token: string }>('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
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
    request<{ domainId: string; instructions: { recordName: string; recordValue: string; note: string } }>(
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
    useCredits = false,
    activeTestConsent?: { riskAccepted: boolean },
    authCredentials?: { username: string; password: string },
    promoCode?: string,
  ) =>
    request<{ orderId: string; paymentPageUrl?: string; paidWithCredits?: boolean; creditsSpent?: number; paidWithPromo?: boolean }>('/orders', {
      method: 'POST',
      body: JSON.stringify({ domainId, packageKey, ...consents, region, useCredits, activeTestConsent, authCredentials, promoCode }),
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
  createBundleOrder: (body: {
    domainId: string; bundleKey: string; selectedModules?: string[];
    ownershipConfirmed: boolean; distanceContractAccepted: boolean; withdrawalWaived: boolean; crossBorderTransfer: boolean;
    region?: string; activeTestConsent?: { riskAccepted: boolean };
    authCredentials?: { username: string; password: string }; promoCode?: string;
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
  // (Is 2) Kredi bakiyesi + satista olan bundle'lar + son hareketler.
  getCredits: () =>
    request<{
      balance: number;
      creditUnitValueMinor: number;
      bundles: Array<{ key: string; displayName: string; credits: number; priceMinorUnit: number; discountPct: number }>;
      transactions: Array<{ delta: number; reason: string; bundleKey: string | null; balanceAfter: number; createdAt: string }>;
    }>('/credits'),
  buyBundle: (bundleKey: string) =>
    request<{ ok: boolean; balance: number; creditsAdded: number }>('/credits/buy-bundle', {
      method: 'POST',
      body: JSON.stringify({ bundleKey }),
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
