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

export const adminApi = {
  login: (email: string, password: string) =>
    areq<{ token: string; email: string }>('/admin/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    }),
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
  scopeViolations: (page = 1) => areq<Page<any>>(`/admin/scope-violations?page=${page}`),
  // (Fatura talebi — MANUEL) Vedat fatura bilgilerini + fiyatı görür, durumu işaretler.
  invoiceRequests: (status = '') =>
    areq<{ total: number; pendingCount: number; items: any[] }>(`/admin/invoice-requests${status ? `?status=${status}` : ''}`),
  updateInvoice: (id: string, body: { status?: 'requested' | 'issued' | 'sent'; notes?: string }) =>
    areq<{ ok: boolean; status: string }>(`/admin/invoice-requests/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  // (SEO BLOG)
  blogList: () =>
    areq<{ posts: Array<{ id: string; title: string; slug: string; status: string; createdAt: string; publishedAt: string | null }>; draftCount: number; publishedCount: number; lastPublishedAt: string | null }>('/admin/blog'),
  blogBulk: (text: string) =>
    areq<{ created: Array<{ title: string; slug: string }>; conflicts: string[]; errors: string[] }>('/admin/blog/bulk', { method: 'POST', body: JSON.stringify({ text }) }),
  blogPublishNext: () =>
    areq<{ ok: boolean; published: { slug: string; title: string } | null; message?: string }>('/admin/blog/publish-next', { method: 'POST' }),
  systemHealth: () => areq<any>('/admin/system-health'),

  // (HER ŞEYİ GÖSTER) Müşteri detay: alan adları + siparişler + raporlar + planlı taramalar + rızalar.
  customerDetail: (id: string) => areq<any>(`/admin/customers/${id}`),
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
  redteamReportBlob: async (id: string, kind: 'html' | 'pdf'): Promise<Blob> => {
    const res = await fetch(`${API_URL}/admin/redteam-jobs/${id}/report.${kind}`, { headers: adminHeaders() });
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
