'use client';
import React from 'react';

export const card: React.CSSProperties = { background: '#1e293b', border: '1px solid #334155', borderRadius: 10, padding: 16 };
const th: React.CSSProperties = { textAlign: 'left', padding: '8px 10px', fontSize: 12, textTransform: 'uppercase', color: '#94a3b8', borderBottom: '1px solid #334155', whiteSpace: 'nowrap' };
const td: React.CSSProperties = { padding: '8px 10px', fontSize: 13, borderBottom: '1px solid #263449', verticalAlign: 'top' };

export function H1({ children }: { children: React.ReactNode }) {
  return <h1 style={{ fontSize: 20, fontWeight: 700, color: '#fff', margin: '0 0 16px' }}>{children}</h1>;
}

export function Table({ columns, rows }: { columns: string[]; rows: React.ReactNode[][] }) {
  return (
    <div style={{ overflowX: 'auto', ...card, padding: 0 }}>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead><tr>{columns.map((c, i) => <th key={i} style={th}>{c}</th>)}</tr></thead>
        <tbody>
          {rows.length === 0
            ? <tr><td style={{ ...td, color: '#64748b' }} colSpan={columns.length}>Kayıt yok.</td></tr>
            : rows.map((r, i) => <tr key={i}>{r.map((cell, j) => <td key={j} style={td}>{cell}</td>)}</tr>)}
        </tbody>
      </table>
    </div>
  );
}

export function Pager({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const btn: React.CSSProperties = { padding: '4px 10px', borderRadius: 6, border: '1px solid #334155', background: '#0f172a', color: '#e2e8f0', cursor: 'pointer', fontSize: 13 };
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 12, fontSize: 13, color: '#94a3b8' }}>
      <button style={{ ...btn, opacity: page <= 1 ? 0.4 : 1 }} disabled={page <= 1} onClick={() => onPage(page - 1)}>← Önceki</button>
      <span>Sayfa {page}/{pages} · toplam {total}</span>
      <button style={{ ...btn, opacity: page >= pages ? 0.4 : 1 }} disabled={page >= pages} onClick={() => onPage(page + 1)}>Sonraki →</button>
    </div>
  );
}

const STATUS_COLOR: Record<string, string> = {
  scan_completed: '#22c55e', report_delivered: '#22c55e', scan_running: '#38bdf8',
  scan_queued: '#eab308', paid: '#a3e635', awaiting_payment: '#94a3b8',
  awaiting_admin_review: '#f59e0b', awaiting_review: '#fbbf24',
  scan_failed: '#ef4444', scope_violation: '#f97316', report_purged: '#64748b', refunded: '#a78bfa',
};
// Kısa Türkçe etiketler (uzun enum yerine panelde okunur).
const STATUS_LABEL: Record<string, string> = {
  awaiting_admin_review: 'rapor onayı bekliyor',
};
export function StatusBadge({ status }: { status: string | null }) {
  if (!status) return <span style={{ color: '#64748b' }}>—</span>;
  const c = STATUS_COLOR[status] ?? '#94a3b8';
  return <span style={{ display: 'inline-block', padding: '2px 8px', borderRadius: 999, fontSize: 12, fontWeight: 600, color: '#0f172a', background: c }}>{STATUS_LABEL[status] ?? status}</span>;
}

export const fmtDate = (d: string | null) => (d ? new Date(d).toLocaleString('tr-TR') : '—');
