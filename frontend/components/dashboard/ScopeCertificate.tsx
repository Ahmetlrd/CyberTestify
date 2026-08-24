type Flow = {
  startedAt?: string | null;
  finishedAt?: string | null;
  toolCallCount?: number | null;
  scopeViolationTarget?: string | null;
};

/**
 * Kapsam Doğrulama Sertifikası — rakiplerde OLMAYAN, gerçek egress-kilidi/scope
 * audit verimizin doğal UI çıktısı. "İddia değil, ölçülebilir kanıt" güven sinyali.
 */
const CERT = {
  tr: {
    title: 'Kapsam Doğrulama Sertifikası', by: 'CyberTestify kapsam kilidi tarafından doğrulandı',
    target: 'Doğrulanan hedef', method: 'Analiz yöntemi', methodVal: 'Kanıt-tabanlı', verified: '· doğrulama ✓',
    access: 'Erişim denetimi', accessVal: 'Kapsam kilidi', active: '· etkin ✓',
    attempts: 'Kapsam dışı erişim girişimi', blocked: 'engellendi',
    footPre: 'Bu tarama, teknik olarak yalnızca ', footMid: ' hedefine erişebildi. ',
    footClean: 'Kapsam dışı hiçbir hedefe erişim girişimi olmadı.', footBlocked: 'Kapsam dışı girişimler proxy tarafından anında engellendi.',
  },
  de: {
    title: 'Scope-Verifizierungszertifikat', by: 'Durch die CyberTestify-Scope-Sperre verifiziert',
    target: 'Verifiziertes Ziel', method: 'Analysemethode', methodVal: 'Nachweisbasiert', verified: '· verifiziert ✓',
    access: 'Zugriffskontrolle', accessVal: 'Scope-Sperre', active: '· aktiv ✓',
    attempts: 'Zugriffsversuche außerhalb des Scope', blocked: 'blockiert',
    footPre: 'Dieser Scan konnte technisch ausschließlich das Ziel ', footMid: ' erreichen. ',
    footClean: 'Es gab keinen Zugriffsversuch auf ein Ziel außerhalb des Scope.', footBlocked: 'Versuche außerhalb des Scope wurden vom Proxy sofort blockiert.',
  },
} as const;

export function ScopeCertificate({ hostname, flow, lang = 'tr' }: { hostname: string; flow?: Flow | null; lang?: 'tr' | 'de' }) {
  const c = CERT[lang === 'de' ? 'de' : 'tr'];
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
          <h3 className="text-sm font-extrabold text-brand">{c.title}</h3>
          <p className="text-xs text-ink-muted">{c.by}</p>
        </div>
      </div>

      <dl className="mt-5 grid grid-cols-2 gap-4">
        <div>
          <dt className="text-xs text-ink-muted">{c.target}</dt>
          <dd className="truncate text-sm font-semibold text-ink" title={hostname}>{hostname}</dd>
        </div>
        <div>
          <dt className="text-xs text-ink-muted">{c.method}</dt>
          <dd className="text-sm font-semibold text-emerald-600">{c.methodVal} <span className="text-xs">{c.verified}</span></dd>
        </div>
        <div>
          <dt className="text-xs text-ink-muted">{c.access}</dt>
          <dd className="text-sm font-semibold text-emerald-600">{c.accessVal} <span className="text-xs">{c.active}</span></dd>
        </div>
        <div>
          <dt className="text-xs text-ink-muted">{c.attempts}</dt>
          <dd className={`text-lg font-extrabold ${clean ? 'text-emerald-600' : 'text-red-600'}`}>
            {clean ? '0' : outOfScope}
            <span className="ml-1 text-xs font-medium">{clean ? '✓' : c.blocked}</span>
          </dd>
        </div>
      </dl>

      <p className="mt-4 border-t border-brand-100 pt-3 text-xs leading-relaxed text-ink-muted">
        {c.footPre}<strong className="text-ink-soft">{hostname}</strong>{c.footMid}
        {clean ? c.footClean : c.footBlocked}
      </p>
    </div>
  );
}
