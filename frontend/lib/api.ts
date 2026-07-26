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
  listPackages: () =>
    request<Array<{ key: string; displayName: string; description: string; priceMinorUnit: number }>>(
      '/orders/packages',
    ),
  createOrder: (
    domainId: string,
    packageKey: string,
    consents: { ownershipConfirmed: boolean; distanceContractAccepted: boolean; withdrawalWaived: boolean },
  ) =>
    request<{ orderId: string; paymentPageUrl: string }>('/orders', {
      method: 'POST',
      body: JSON.stringify({ domainId, packageKey, ...consents }),
    }),
  getOrder: (orderId: string) => request<any>(`/orders/${orderId}`),
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
