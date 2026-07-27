'use client';

import { useEffect, useState } from 'react';
import { adminApi } from '../../../lib/adminApi';
import { H1, card } from '../../../components/admin/ui';

function Stat({ label, value, color }: { label: string; value: React.ReactNode; color?: string }) {
  return (
    <div style={{ ...card, minWidth: 160 }}>
      <div style={{ fontSize: 12, textTransform: 'uppercase', color: '#94a3b8', letterSpacing: 0.4 }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 700, color: color ?? '#fff', marginTop: 6 }}>{value}</div>
    </div>
  );
}

function Health({ ok, label }: { ok: boolean; label: string }) {
  return (
    <div style={{ ...card, display: 'flex', alignItems: 'center', gap: 10 }}>
      <span style={{ width: 12, height: 12, borderRadius: 999, background: ok ? '#22c55e' : '#ef4444', boxShadow: `0 0 8px ${ok ? '#22c55e' : '#ef4444'}` }} />
      <div>
        <div style={{ fontSize: 13, color: '#e2e8f0', fontWeight: 600 }}>{label}</div>
        <div style={{ fontSize: 12, color: ok ? '#22c55e' : '#ef4444' }}>{ok ? 'Sağlıklı' : 'ERİŞİLEMİYOR'}</div>
      </div>
    </div>
  );
}

export default function AdminDashboard() {
  const [h, setH] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = () => adminApi.systemHealth().then(setH).catch((e) => setError(e.message));
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);

  if (error) return <><H1>Özet</H1><p style={{ color: '#fca5a5' }}>{error}</p></>;
  if (!h) return <><H1>Özet</H1><p style={{ color: '#94a3b8' }}>Yükleniyor…</p></>;

  const diskColor = h.diskUsedPct >= 80 ? '#ef4444' : h.diskUsedPct >= 60 ? '#eab308' : '#22c55e';

  return (
    <>
      <H1>Özet</H1>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 16 }}>
        <Health ok={h.egressProxyHealthy} label="Egress-proxy (kapsam kilidi)" />
        <Health ok={h.pentagiHealthy} label="PentAGI" />
      </div>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <Stat label="Aktif tarama" value={h.activeScans} color={h.activeScans > 0 ? '#38bdf8' : '#fff'} />
        <Stat label="Kuyrukta bekleyen" value={h.queuedOrders} color={h.queuedOrders >= 20 ? '#f97316' : '#fff'} />
        <Stat label="Son 24s yeni müşteri" value={h.newCustomers24h} />
        <Stat label="Disk kullanımı" value={h.diskUsedPct != null ? `%${h.diskUsedPct}` : '—'} color={diskColor} />
        <Stat label="Kapsam modu" value={h.scopeEnforcement} />
      </div>
      <p style={{ fontSize: 12, color: '#64748b', marginTop: 16 }}>
        Disk: {h.diskRaw} · Kontrol: {new Date(h.checkedAt).toLocaleTimeString('tr-TR')} · 15 sn'de bir yenilenir.
      </p>
    </>
  );
}
