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
    throw new Error(body.error ? JSON.stringify(body.error) : `İstek başarısız: ${res.status}`);
  }
  return res.json();
}

export const api = {
  register: (email: string, password: string, termsAccepted: boolean) =>
    request<{ token: string }>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, termsAccepted }),
    }),
  login: (email: string, password: string) =>
    request<{ token: string }>('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  createDomain: (hostname: string) =>
    request<{ domainId: string; instructions: { recordName: string; recordValue: string; note: string } }>(
      '/domains',
      { method: 'POST', body: JSON.stringify({ hostname }) },
    ),
  verifyDomain: (domainId: string) =>
    request<{ verified: boolean }>(`/domains/${domainId}/verify`, { method: 'POST' }),
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
    request<Array<{ key: string; displayName: string; description: string; priceMinorUnit: number; currency?: string }>>(
      `/orders/packages?region=${region}`,
    ),
  createOrder: (
    domainId: string,
    packageKey: string,
    consents: { ownershipConfirmed: boolean; distanceContractAccepted: boolean; withdrawalWaived: boolean },
    region = 'tr',
  ) =>
    request<{ orderId: string; paymentPageUrl: string }>('/orders', {
      method: 'POST',
      body: JSON.stringify({ domainId, packageKey, ...consents, region }),
    }),
  getOrder: (orderId: string) => request<any>(`/orders/${orderId}`),
  listOrders: () =>
    request<
      Array<{ id: string; hostname: string; packageName: string; status: string; createdAt: string }>
    >('/orders'),
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
};
