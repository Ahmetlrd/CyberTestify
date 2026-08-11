const STEPS = [
  { key: 'verify', label: 'Sahiplik doğrulandı', hint: 'Alan adınızın sizin olduğu teyit edildi' },
  { key: 'scan', label: 'Tarama çalışıyor', hint: 'Yapay zekâ destekli tarama sitenizi güvenli şekilde inceliyor' },
  { key: 'analyze', label: 'Bulgular değerlendiriliyor', hint: 'Sonuçlar önem derecesine göre sıralanıyor' },
  { key: 'report', label: 'Rapor hazır', hint: 'Şifreli raporunuz oluşturuldu' },
];

// order.status -> kac adim TAMAMLANDI (active = ilk tamamlanmayan)
function completedCount(status: string): number {
  switch (status) {
    case 'awaiting_payment':
    case 'paid':
    case 'scan_queued':
      return 1; // dogrulama bitti, tarama basliyor/sirada
    case 'scan_running':
      return 1;
    case 'scan_completed':
    case 'report_delivered':
      return 4;
    default:
      return 1;
  }
}

function Spinner() {
  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4 animate-spin text-brand" fill="none">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.2" strokeWidth="3" />
      <path d="M21 12a9 9 0 00-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

export function StatusTracker({ status }: { status: string }) {
  const failed = status === 'scan_failed' || status === 'scope_violation';
  const done = completedCount(status);
  const queued = status === 'scan_queued';

  return (
    <div className="card p-6">
      {queued && (
        <div className="mb-4 rounded-card bg-accent-soft px-4 py-2.5 text-sm font-medium text-accent-600">
          Siparişiniz alındı, taramanız sırada. Şu an başka bir tarama çalışıyor; sıranız gelince
          otomatik başlayacak — bu sayfa kendiliğinden güncellenir ve <strong>başladığında size e-posta
          göndeririz</strong>.
        </div>
      )}
      <ol className="space-y-1">
        {STEPS.map((s, i) => {
          const isDone = i < done && !failed;
          const isActive = i === done && !failed && status !== 'scan_completed';
          const isFailedHere = failed && i === done;
          const last = i === STEPS.length - 1;
          return (
            <li key={s.key} className="flex gap-3">
              <div className="flex flex-col items-center">
                <span
                  className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full border-2 transition ${
                    isDone
                      ? 'border-brand bg-brand text-white'
                      : isActive
                        ? 'border-accent bg-white animate-pulse-ring'
                        : isFailedHere
                          ? 'border-red-400 bg-red-50 text-red-500'
                          : 'border-line bg-white text-ink-muted'
                  }`}
                >
                  {isDone ? (
                    <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M5 13l4 4L19 7" />
                    </svg>
                  ) : isActive ? (
                    <Spinner />
                  ) : isFailedHere ? (
                    <span className="text-sm font-bold">!</span>
                  ) : (
                    <span className="text-xs font-semibold">{i + 1}</span>
                  )}
                </span>
                {!last && <span className={`my-1 w-0.5 flex-1 ${isDone ? 'bg-brand/40' : 'bg-line'}`} style={{ minHeight: 18 }} />}
              </div>
              <div className={`pb-4 ${!isDone && !isActive && !isFailedHere ? 'opacity-50' : ''}`}>
                <div className={`text-sm font-semibold ${isFailedHere ? 'text-red-600' : 'text-ink'}`}>{s.label}</div>
                <div className="text-xs text-ink-muted">{s.hint}</div>
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
