type Flow = {
  startedAt?: string | null;
  finishedAt?: string | null;
  toolCallCount?: number | null;
  scopeViolationTarget?: string | null;
};

function formatDuration(start?: string | null, end?: string | null): string {
  if (!start || !end) return '—';
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (!Number.isFinite(ms) || ms < 0) return '—';
  const s = Math.round(ms / 1000);
  const m = Math.floor(s / 60);
  const rs = s % 60;
  return m > 0 ? `${m} dk ${rs} sn` : `${rs} sn`;
}

/**
 * Kapsam Doğrulama Sertifikası — rakiplerde OLMAYAN, gerçek egress-kilidi/scope
 * audit verimizin doğal UI çıktısı. "İddia değil, ölçülebilir kanıt" güven sinyali.
 */
export function ScopeCertificate({ hostname, flow }: { hostname: string; flow?: Flow | null }) {
  const outOfScope = flow?.scopeViolationTarget
    ? flow.scopeViolationTarget.split(',').filter(Boolean).length
    : 0;
  const clean = outOfScope === 0;

  return (
    <div className="relative overflow-hidden rounded-card border border-brand-300 bg-brand-50/60 p-6 shadow-glow">
      <div className="pointer-events-none absolute -right-8 -top-8 h-28 w-28 rounded-full bg-brand/5" />
      <div className="flex items-center gap-2.5">
        <span className="flex h-9 w-9 items-center justify-center rounded-full bg-brand text-accent">
          <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 2l7 4v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6l7-4zM9 12l2 2 4-4" />
          </svg>
        </span>
        <div>
          <h3 className="text-sm font-extrabold text-brand">Kapsam Doğrulama Sertifikası</h3>
          <p className="text-xs text-ink-muted">CyberTestify egress kilidi tarafından doğrulandı</p>
        </div>
      </div>

      <dl className="mt-5 grid grid-cols-2 gap-4">
        <div>
          <dt className="text-xs text-ink-muted">Doğrulanan hedef</dt>
          <dd className="truncate text-sm font-semibold text-ink" title={hostname}>{hostname}</dd>
        </div>
        <div>
          <dt className="text-xs text-ink-muted">Tarama süresi</dt>
          <dd className="text-sm font-semibold text-ink">{formatDuration(flow?.startedAt, flow?.finishedAt)}</dd>
        </div>
        <div>
          <dt className="text-xs text-ink-muted">Yürütülen işlem</dt>
          <dd className="text-sm font-semibold text-ink">{flow?.toolCallCount ?? 0} adım</dd>
        </div>
        <div>
          <dt className="text-xs text-ink-muted">Kapsam dışı erişim girişimi</dt>
          <dd className={`text-lg font-extrabold ${clean ? 'text-emerald-600' : 'text-red-600'}`}>
            {clean ? '0' : outOfScope}
            <span className="ml-1 text-xs font-medium">{clean ? '✓' : 'engellendi'}</span>
          </dd>
        </div>
      </dl>

      <p className="mt-4 border-t border-brand-100 pt-3 text-xs leading-relaxed text-ink-muted">
        Bu tarama, teknik olarak yalnızca <strong className="text-ink-soft">{hostname}</strong> hedefine
        erişebildi. {clean ? 'Kapsam dışı hiçbir hedefe erişim girişimi olmadı.' : 'Kapsam dışı girişimler proxy tarafından anında engellendi.'}
      </p>
    </div>
  );
}
