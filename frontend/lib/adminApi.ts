// Admin paneli API istemcisi — MUSTERI api.ts'ten AYRI. Ayri token anahtari
// ('admin_token') kullanir; musteri oturumuyla KARISMAZ.
const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

export const ADMIN_TOKEN_KEY = 'admin_token';

function adminHeaders(): Record<string, string> {
  if (typeof window === 'undefined') return {};
  const t = window.localStorage.getItem(ADMIN_TOKEN_KEY);
  return t ? { Authorization: `Bearer ${t}` } : {};
}

// Hatayı her zaman TEMİZ bir cümleye indirger — ham Zod objesi / "[object Object]" gösterme.
function friendlyAdminError(body: any, status: number, fallback: string): string {
  const e = body?.error;
  if (typeof e === 'string' && e.trim()) return e;
  if (e && typeof e === 'object') {
    const fe = (e as any).fieldErrors;
    if (fe && typeof fe === 'object') for (const v of Object.values(fe)) if (Array.isArray(v) && v[0]) return String(v[0]);
    if (Array.isArray((e as any).formErrors) && (e as any).formErrors[0]) return String((e as any).formErrors[0]);
  }
  return typeof body?.message === 'string' && body.message.trim() ? body.message : fallback;
}

async function areq<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...adminHeaders(), ...options.headers },
  });
  // (KAYAN OTURUM) Sunucu token'i yenilediyse sakla → panel aktif kullanildikca oturum düşmez.
  const refreshed = res.headers.get('X-Admin-Token-Refresh');
  if (refreshed && typeof window !== 'undefined') window.localStorage.setItem(ADMIN_TOKEN_KEY, refreshed);
  if (res.status === 401 && typeof window !== 'undefined' && !path.endsWith('/login')) {
    window.localStorage.removeItem(ADMIN_TOKEN_KEY);
    window.location.href = '/admin/login';
  }
  if (!res.ok) {
    const b = await res.json().catch(() => ({}));
    throw new Error(friendlyAdminError(b, res.status, 'İşlem şu an tamamlanamadı. Lütfen tekrar deneyin.'));
  }
  return res.json();
}

type Page<T> = { page: number; pageSize: number; total: number; items: T[] };

// Stage-token (2FA ara token) ile istek — stored admin token'ı DEĞİL, verilen bearer'ı kullanır.
async function areqStage<T>(path: string, bearer: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}`, ...options.headers },
  });
  if (!res.ok) { const b = await res.json().catch(() => ({})); throw new Error(friendlyAdminError(b, res.status, 'İşlem şu an tamamlanamadı.')); }
  return res.json();
}

export const adminApi = {
  // Adım 1: mail+şifre. Dönüş: tam token DEĞİL — 2FA gerekli/enrollment gerekli + stageToken.
  login: (email: string, password: string) =>
    areq<{ token?: string; email?: string; twofaRequired?: boolean; enrollmentRequired?: boolean; stageToken?: string }>('/admin/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    }),
  // Adım 2: TOTP/kurtarma kodu → tam token.
  login2fa: (stageToken: string, code: string) =>
    areq<{ token: string; email: string }>('/admin/auth/login/2fa', { method: 'POST', body: JSON.stringify({ stageToken, code }) }),
  // Enrollment: QR + manuel anahtar (stageToken=enroll ile).
  twofaSetup: (stageToken: string) =>
    areqStage<{ otpauthUri: string; qrDataUrl: string; manualKey: string }>('/admin/auth/2fa/setup', stageToken),
  // Enrollment onay: kod → tam token + kurtarma kodları.
  twofaEnable: (stageToken: string, code: string) =>
    areqStage<{ token: string; email: string; recoveryCodes: string[] }>('/admin/auth/2fa/enable', stageToken, { method: 'POST', body: JSON.stringify({ code }) }),
  customers: (page = 1) =>
    areq<Page<{ id: string; email: string; createdAt: string; domainCount: number; orderCount: number }>>(
      `/admin/customers?page=${page}`,
    ),
  orders: (page = 1, status = '') =>
    areq<Page<any> & { statusFilter: string | null }>(
      `/admin/orders?page=${page}${status ? `&status=${status}` : ''}`,
    ),
  order: (id: string) => areq<any>(`/admin/orders/${id}`),
  // (GÖZLEMLENEBİLİRLİK) Taramanın adım-adım logu (kronolojik).
  scanLogs: (id: string) => areq<{ order: any; count: number; logs: any[] }>(`/admin/orders/${id}/logs`),
  // (E) Iade olarak isaretle — 'refunded' + musteriye iade bildirim maili (backend).
  refundOrder: (id: string) => areq<{ ok: boolean; mailed?: boolean; alreadyRefunded?: boolean }>(`/admin/orders/${id}/refund`, { method: 'POST' }),

  // (İÇ KALİTE KAPISI) Rapor onay akışı.
  approveReport: (id: string) => areq<{ ok: boolean; released: boolean; mailed: boolean }>(`/admin/orders/${id}/approve-report`, { method: 'POST' }),
  retryScan: (id: string) => areq<{ ok: boolean; retried: boolean; queued: boolean }>(`/admin/orders/${id}/retry-scan`, { method: 'POST' }),
  // Şifreli raporu (AI dahil açık) PDF blob olarak çek — auth header gerektiği için <a href> yerine fetch.
  reportPdfBlob: async (id: string): Promise<Blob> => {
    const res = await fetch(`${API_URL}/admin/orders/${id}/report.pdf`, { headers: adminHeaders() });
    if (res.status === 401 && typeof window !== 'undefined') {
      window.localStorage.removeItem(ADMIN_TOKEN_KEY);
      window.location.href = '/admin/login';
    }
    if (!res.ok) {
      const b = await res.json().catch(() => ({}));
      throw new Error(friendlyAdminError(b, res.status, 'Rapor şu an alınamadı. Lütfen tekrar deneyin.'));
    }
    return res.blob();
  },
  // (LINKEDIN OTOMATİK PAYLAŞIM — Buffer GraphQL API) Yalnız admin; API anahtarı BACKEND'de kalır.
  linkedinStatus: () =>
    areq<{ enabled: boolean; error?: string; channelId?: string; channelName?: string; organizationId?: string }>('/admin/linkedin/status'),
  linkedinPosts: (status = '') =>
    areq<{ items: any[]; pendingCount: number }>(`/admin/linkedin/posts${status ? `?status=${status}` : ''}`),
  linkedinCreate: (body: { content: string; mediaUrl?: string; mode: 'addToQueue' | 'customScheduled'; scheduledFor?: string }) =>
    areq<{ ok: boolean; post: any }>('/admin/linkedin/posts', { method: 'POST', body: JSON.stringify(body) }),
  linkedinDelete: (id: string) => areq<{ ok: boolean }>(`/admin/linkedin/posts/${id}`, { method: 'DELETE' }),
  linkedinSync: () => areq<{ ok: boolean; checked: number; updated: number }>('/admin/linkedin/sync', { method: 'POST' }),
  linkedinAssets: () =>
    areq<{ items: Array<{ id: string; kind: string; title: string; bytes: number; pages: number | null; createdAt: string; url: string }> }>('/admin/linkedin/assets'),
  linkedinMakeCarousel: (body: { title: string; slides: Array<Record<string, unknown>> }) =>
    areq<{ ok: boolean; id: string; url: string; thumbnailUrl: string; bytes: number; pages: number }>('/admin/linkedin/assets/carousel', { method: 'POST', body: JSON.stringify(body) }),
  scopeViolations: (page = 1) => areq<Page<any>>(`/admin/scope-violations?page=${page}`),
  instantScanLogs: (page = 1, q = '') =>
    areq<{ page: number; pageSize: number; total: number; uniqueHosts: number; last24h: number; items: Array<{ id: string; host: string; status: string; score: number | null; grade: string | null; findings: number | null; httpStatus: number | null; region: string; ip: string | null; createdAt: string }> }>(`/admin/instant-scan-logs?page=${page}${q ? `&q=${encodeURIComponent(q)}` : ''}`),
  // (Fatura talebi — MANUEL) Vedat fatura bilgilerini + fiyatı görür, durumu işaretler.
  invoiceRequests: (status = '') =>
    areq<{ total: number; pendingCount: number; items: any[] }>(`/admin/invoice-requests${status ? `?status=${status}` : ''}`),
  updateInvoice: (id: string, body: { status?: 'requested' | 'issued' | 'sent'; notes?: string }) =>
    areq<{ ok: boolean; status: string }>(`/admin/invoice-requests/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  // (SEO BLOG — çok-dilli: tr | de)
  blogList: (lang?: 'tr' | 'de' | 'en') =>
    areq<{ posts: Array<{ id: string; title: string; slug: string; status: string; lang: string; createdAt: string; publishedAt: string | null }>; draftCount: number; publishedCount: number; lastPublishedAt: string | null }>(`/admin/blog${lang ? `?lang=${lang}` : ''}`),
  blogBulk: (text: string, lang: 'tr' | 'de' | 'en' = 'tr') =>
    areq<{ created: Array<{ title: string; slug: string }>; conflicts: string[]; errors: string[]; lang: string }>('/admin/blog/bulk', { method: 'POST', body: JSON.stringify({ text, lang }) }),
  blogPublishNext: (lang?: 'tr' | 'de' | 'en') =>
    areq<{ ok: boolean; published: { slug: string; title: string } | null; message?: string }>('/admin/blog/publish-next', { method: 'POST', body: JSON.stringify(lang ? { lang } : {}) }),
  // (BLOG FOTOLAR) kategori-etiketli görsel kütüphanesi + makale kapak override
  blogCategories: () => areq<Array<{ slug: string; label: { tr: string; de: string; en: string } }>>('/admin/blog-categories'),
  blogImages: (category?: string) =>
    areq<Array<{ id: string; category: string; mime: string; width: number | null; height: number | null; alt: string | null; usedCount: number; lastUsedAt: string | null; createdAt: string }>>(`/admin/blog-images${category ? `?category=${category}` : ''}`),
  blogImageUpload: (body: { category: string; dataBase64: string; width?: number; height?: number; alt?: string }) =>
    areq<{ ok: boolean; image: { id: string } }>('/admin/blog-images', { method: 'POST', body: JSON.stringify(body) }),
  blogImageDelete: (id: string) => areq<{ ok: boolean }>(`/admin/blog-images/${id}`, { method: 'DELETE' }),
  blogCoverReroll: (postId: string) => areq<{ ok: boolean; coverImageId: string | null }>(`/admin/blog/${postId}/cover/reroll`, { method: 'POST', body: '{}' }),
  blogCoverSet: (postId: string, imageId: string) => areq<{ ok: boolean; coverImageId: string }>(`/admin/blog/${postId}/cover`, { method: 'POST', body: JSON.stringify({ imageId }) }),
  blogGet: (id: string) => areq<{ id: string; title: string; description: string; slug: string; lang: string; status: string; contentMd: string; category: string | null }>(`/admin/blog/${id}`),
  blogUpdate: (id: string, patch: { title?: string; description?: string; contentMd?: string; category?: string }) =>
    areq<{ ok: boolean }>(`/admin/blog/${id}`, { method: 'PATCH', body: JSON.stringify(patch) }),
  blogDelete: (id: string) => areq<{ ok: boolean; deleted?: { title: string; slug: string } }>(`/admin/blog/${id}`, { method: 'DELETE' }),
  systemHealth: () => areq<any>('/admin/system-health'),

  // (HER ŞEYİ GÖSTER) Müşteri detay: alan adları + siparişler + raporlar + planlı taramalar + rızalar.
  customerDetail: (id: string) => areq<any>(`/admin/customers/${id}`),
  // (TEMİZLİK) Müşteri hesabını ve TÜM bağlı verisini (sipariş/rapor/alan adı/plan/onay/fatura) siler.
  // Yanlışlıkla silmeye karşı sunucu tarafında da e-posta teyidi ZORUNLU (confirmEmail).
  customerDelete: (id: string, confirmEmail: string) =>
    areq<{ ok: boolean; email: string; deleted: Record<string, number> }>(`/admin/customers/${id}`, {
      method: 'DELETE', body: JSON.stringify({ confirmEmail }),
    }),
  // Tüm alan adları (global; müşteri e-postasıyla).
  domains: (page = 1, q = '') => areq<Page<any>>(`/admin/domains?page=${page}${q ? `&q=${encodeURIComponent(q)}` : ''}`),

  // (OTONOM RED TEAM — canlı gözlem; yalnız admin) faz/log/cap/egress/bulgu/kill-switch/maliyet.
  redteamJobs: (page = 1) => areq<Page<any>>(`/admin/redteam-jobs?page=${page}`),
  redteamJob: (id: string) => areq<any>(`/admin/redteam-jobs/${id}`),
  redteamJobLogs: (id: string, after = 0) =>
    areq<{ logs: Array<{ seq: number; at: string; source: string; phase: string | null; level: string; message: string }> }>(
      `/admin/redteam-jobs/${id}/logs?after=${after}`,
    ),
  redteamKill: (id: string) => areq<{ ok: boolean; verified: 'destroyed' | 'unverified' | 'skipped'; error: string | null; reportGenerated: boolean }>(`/admin/redteam-jobs/${id}/kill`, { method: 'POST' }),
  // (MODEL YÖNETİMİ + MALİYET + CANLI TETİK)
  redteamModelCatalog: () =>
    areq<{ catalog: Array<{ id: string; label: string; tier: string; price: { inM: number; outM: number }; expensive: boolean }>; roles: string[]; defaults: Record<string, string>; levels: Record<string, { capSec: number; capCalls: number; capCostUsd: number; size: string; profile: string }> }>(
      '/admin/redteam/model-catalog',
    ),
  redteamEstimate: (body: { level: string; modelConfig?: Record<string, string>; capCallsOverride?: number }) =>
    areq<{ estUsd: number; dominantModel: string; hasOpus: boolean; note: string; perModel: Array<{ model: string; sharePct: number; estUsd: number }> }>(
      '/admin/redteam/estimate', { method: 'POST', body: JSON.stringify(body) },
    ),
  redteamCreate: (body: { domain: string; level: string; modelConfig?: Record<string, string>; capCallsOverride?: number; capSecOverride?: number; capCostOverride?: number; dryRun?: boolean }) =>
    areq<{ ok: boolean; jobId: string; dryRun: boolean; estimate: any }>('/admin/redteam-jobs', { method: 'POST', body: JSON.stringify(body) }),
  // Tam rapor: okunur HTML + indirilebilir PDF (auth header gerektiği için fetch→blob).
  redteamReportBlob: async (id: string, kind: 'html' | 'pdf', view?: 'customer'): Promise<Blob> => {
    const qs = view === 'customer' ? '?view=customer' : '';
    const res = await fetch(`${API_URL}/admin/redteam-jobs/${id}/report.${kind}${qs}`, { headers: adminHeaders() });
    if (res.status === 401 && typeof window !== 'undefined') { window.localStorage.removeItem(ADMIN_TOKEN_KEY); window.location.href = '/admin/login'; }
    if (!res.ok) { const b = await res.json().catch(() => ({})); throw new Error(friendlyAdminError(b, res.status, 'Rapor şu an alınamadı.')); }
    return res.blob();
  },

  // (HESAP VEREBİLİRLİK) Admin rapor-erişim audit'i (değiştirilemez; secret içermez).
  reportAccessLogs: (page = 1, opts: { reportId?: string; customerId?: string } = {}) =>
    areq<Page<{ id: string; at: string; adminId: string; reportId: string; orderId: string; customerId: string; customerEmail: string; action: string; ip: string | null }>>(
      `/admin/report-access-logs?page=${page}${opts.reportId ? `&reportId=${opts.reportId}` : ''}${opts.customerId ? `&customerId=${opts.customerId}` : ''}`,
    ),
};
