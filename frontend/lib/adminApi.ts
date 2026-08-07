// Admin paneli API istemcisi — MUSTERI api.ts'ten AYRI. Ayri token anahtari
// ('admin_token') kullanir; musteri oturumuyla KARISMAZ.
const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

export const ADMIN_TOKEN_KEY = 'admin_token';

function adminHeaders(): Record<string, string> {
  if (typeof window === 'undefined') return {};
  const t = window.localStorage.getItem(ADMIN_TOKEN_KEY);
  return t ? { Authorization: `Bearer ${t}` } : {};
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
    throw new Error(b.error ? (typeof b.error === 'string' ? b.error : JSON.stringify(b.error)) : `İstek başarısız: ${res.status}`);
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
  // (E) Iade olarak isaretle — 'refunded' + musteriye iade bildirim maili (backend).
  refundOrder: (id: string) => areq<{ ok: boolean; mailed?: boolean; alreadyRefunded?: boolean }>(`/admin/orders/${id}/refund`, { method: 'POST' }),
  scopeViolations: (page = 1) => areq<Page<any>>(`/admin/scope-violations?page=${page}`),
  // (SEO BLOG)
  blogList: () =>
    areq<{ posts: Array<{ id: string; title: string; slug: string; status: string; createdAt: string; publishedAt: string | null }>; draftCount: number; publishedCount: number; lastPublishedAt: string | null }>('/admin/blog'),
  blogBulk: (text: string) =>
    areq<{ created: Array<{ title: string; slug: string }>; conflicts: string[]; errors: string[] }>('/admin/blog/bulk', { method: 'POST', body: JSON.stringify({ text }) }),
  blogPublishNext: () =>
    areq<{ ok: boolean; published: { slug: string; title: string } | null; message?: string }>('/admin/blog/publish-next', { method: 'POST' }),
  systemHealth: () => areq<any>('/admin/system-health'),
};
