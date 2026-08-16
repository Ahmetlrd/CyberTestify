'use client';

import { useCallback, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { api } from '../../lib/api';

type Domain = {
  id: string;
  hostname: string;
  status: string;
  verifiedAt: string | null;
  valid: boolean;
  instructions: { recordName: string; recordValue: string };
};

type Order = {
  id: string;
  hostname: string;
  packageName: string;
  status: string;
  createdAt: string;
  archived: boolean;
  paid?: boolean;
  invoiceStatus?: 'requested' | 'issued' | 'sent' | null;
};

const ORDER_STATUS_LABEL: Record<string, string> = {
  awaiting_payment: 'Ödeme bekleniyor',
  paid: 'Sıraya alınıyor',
  scan_queued: 'Başlatılıyor',
  scan_running: 'Taranıyor',
  // (Savunma) İç kalite kapısı durumu backend'de zaten 'scan_running'e maskelenir; yine de
  // hiçbir koşulda ham enum sızmasın diye burada da "Taranıyor" gösterilir.
  awaiting_admin_review: 'Taranıyor',
  scan_completed: 'Rapor hazır',
  report_delivered: 'Rapor hazır',
  scan_failed: 'Başarısız',
  scope_violation: 'Durduruldu (kapsam dışı)',
  report_purged: 'Süresi doldu',
  refunded: 'İade edildi',
};

const HISTORY_PREVIEW = 3;

// Kullanıcı "https://www.ornek.com/path" gibi girebilir; backend'le AYNI kuralla çıplak host'a
// indir (şema/www/port/path at) ki kullanıcı ne ekleneceğini önceden görsün. (Asıl doğrulama
// backend'de normalizeHostname ile tekrar yapılır — bu yalnız önizleme/UX.)
function previewHostname(input: string): string {
  return (input ?? '')
    .trim()
    .toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
    .replace(/^[^/@]*@/, '')
    .replace(/[/?#].*$/, '')
    .replace(/:\d+$/, '')
    .replace(/^www\./, '')
    .replace(/\.+$/, '');
}

export default function VerifyHub() {
  const router = useRouter();
  // Satın-alma akışı: paketler sayfasından "Satın Al" ile gelindiyse paket/bundle taşınır.
  const params = useSearchParams();
  const packageParam = params.get('package');
  const bundleParam = params.get('bundle');
  const purchaseMode = !!(packageParam || bundleParam);
  const purchaseQuery = packageParam ? `&package=${packageParam}` : bundleParam ? `&bundle=${bundleParam}` : '';

  const [domains, setDomains] = useState<Domain[]>([]);
  const [orders, setOrders] = useState<Order[]>([]);
  const [archivedOrders, setArchivedOrders] = useState<Order[] | null>(null);
  const [showAllHistory, setShowAllHistory] = useState(false);
  const [showArchived, setShowArchived] = useState(false);
  const [loading, setLoading] = useState(true);
  const [newHostname, setNewHostname] = useState('');
  const [openId, setOpenId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [showAdd, setShowAdd] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  // (İŞ 2) Panel sekmeleri — dağınık iç içe bölümler yerine net ayrım.
  const [tab, setTab] = useState<'domains' | 'history'>('domains');

  const refresh = useCallback(async () => {
    const [list, ord] = await Promise.all([api.listDomains(), api.listOrders(false)]);
    setDomains(list);
    setOrders(ord as Order[]);
    if (showArchived) setArchivedOrders((await api.listOrders(true)) as Order[]);
    return list;
  }, [showArchived]);

  useEffect(() => {
    if (typeof window !== 'undefined' && !window.localStorage.getItem('token')) {
      // Satın-alma niyeti korunsun: login sonrası aynı URL'e dön.
      const next = typeof window !== 'undefined' ? window.location.pathname + window.location.search : '/verify';
      router.push(`/login?next=${encodeURIComponent(next)}`);
      return;
    }
    refresh()
      .catch((e: any) => setError(e.message))
      .finally(() => setLoading(false));
  }, [router, refresh]);

  const goToOrder = (domainId: string) => router.push(`/order?domainId=${domainId}${purchaseQuery}`);

  async function addDomain(e: React.FormEvent) {
    e.preventDefault();
    if (!newHostname.trim() || busy) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await api.createDomain(newHostname.trim());
      setNewHostname('');
      setShowAdd(false);
      await refresh();
      setOpenId(res.domainId);
      // Zaten ekli + doğrulanmışsa: onaylı kayıt KORUNUR (yeniden DNS doğrulama yok) + net bilgi.
      if (res.alreadyVerified) setNotice(res.message || `“${res.hostname}” zaten ekli ve doğrulanmış.`);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function check(id: string) {
    setBusy(true);
    setError(null);
    try {
      const { verified } = await api.verifyDomain(id);
      await refresh();
      if (verified) goToOrder(id);
      else setError('Kayıt henüz görünmüyor. DNS yayılımı biraz sürebilir; birazdan tekrar deneyin.');
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function del(id: string) {
    if (!window.confirm('Bu alan adını silmek istediğinize emin misiniz? Bu işlem geri alınamaz.')) return;
    setError(null);
    try {
      await api.deleteDomain(id);
      await refresh();
    } catch (e: any) {
      setError(e.message);
    }
  }

  async function delAll() {
    if (!window.confirm('Taraması olmayan tüm alan adları silinsin mi?')) return;
    setError(null);
    try {
      const r = await api.deleteAllDomains();
      await refresh();
      if (r.kept > 0) setError(`${r.deleted} alan adı silindi; taraması olan ${r.kept} tanesi korundu.`);
    } catch (e: any) {
      setError(e.message);
    }
  }

  async function archiveOrder(id: string, archived: boolean) {
    setError(null);
    try {
      await api.archiveOrder(id, archived);
      await refresh();
    } catch (e: any) {
      setError(e.message);
    }
  }

  async function deleteOrder(id: string) {
    if (!window.confirm('Bu raporu silmek istediğinize emin misiniz? Bu işlem geri alınamaz.')) return;
    setError(null);
    try {
      await api.deleteOrder(id);
      await refresh();
    } catch (e: any) {
      setError(e.message);
    }
  }

  async function toggleArchived() {
    const next = !showArchived;
    setShowArchived(next);
    if (next && archivedOrders === null) {
      try {
        setArchivedOrders((await api.listOrders(true)) as Order[]);
      } catch (e: any) {
        setError(e.message);
      }
    }
  }

  const validDomains = domains.filter((d) => d.valid);
  const pendingDomains = domains.filter((d) => !d.valid);
  const shownHistory = showAllHistory ? orders : orders.slice(0, HISTORY_PREVIEW);

  // --- Alan adı seçim/ekleme bölümü (hem normal hem satın-alma modunda kullanılır) ---
  const domainSection = (
    <>
      {validDomains.length > 0 && (
        <section className="mt-8">
          <h2 className="text-sm font-bold uppercase tracking-wide text-ink-muted">Doğrulanmış alan adların</h2>
          <div className="mt-3 space-y-2.5">
            {validDomains.map((d) => (
              <div key={d.id} className="card flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0">
                  <div className="truncate font-semibold text-ink">{d.hostname}</div>
                  <span className="mt-0.5 inline-flex items-center gap-1 text-xs font-medium text-emerald-600">
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" /> Doğrulandı · geçerli
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-2 sm:shrink-0">
                  <button onClick={() => goToOrder(d.id)} className="btn-primary">
                    {purchaseMode ? 'Bu alan adı ile devam et' : 'Taramayı Başlat'}
                  </button>
                  {!purchaseMode && (
                    <button onClick={() => del(d.id)} className="btn-ghost text-sm text-red-600">
                      Sil
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {pendingDomains.length > 0 && (
        <section className="mt-8">
          <h2 className="text-sm font-bold uppercase tracking-wide text-ink-muted">Doğrulama bekleyen</h2>
          <div className="mt-3 space-y-2.5">
            {pendingDomains.map((d) => {
              const expired = d.status === 'verified' && !d.valid;
              const open = openId === d.id;
              return (
                <div key={d.id} className="card p-4">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <div className="min-w-0">
                      <div className="truncate font-semibold text-ink">{d.hostname}</div>
                      <span className={`mt-0.5 text-xs font-medium ${expired ? 'text-red-600' : 'text-amber-600'}`}>
                        {expired ? 'Süresi doldu — yeniden doğrula' : 'Henüz doğrulanmadı'}
                      </span>
                    </div>
                    <div className="flex flex-wrap items-center gap-2 sm:shrink-0">
                      <button onClick={() => setOpenId(open ? null : d.id)} className="btn-outline text-sm">
                        {open ? 'Gizle' : 'Doğrula'}
                      </button>
                      <button onClick={() => del(d.id)} className="btn-ghost text-sm text-red-600">
                        Sil
                      </button>
                    </div>
                  </div>
                  {open && (
                    <div className="mt-4 border-t border-line pt-4">
                      <p className="text-sm text-ink-soft">DNS panelinize aşağıdaki <strong>TXT</strong> kaydını ekleyin:</p>
                      <div className="mt-2 space-y-2 rounded-card bg-brand-deep p-3.5 font-mono text-xs text-white/90">
                        <div>
                          <span className="text-white/45">Ad:</span>{' '}
                          <span className="break-all text-emerald-300">{d.instructions.recordName}</span>
                        </div>
                        <div>
                          <span className="text-white/45">Değer:</span>{' '}
                          <span className="break-all text-accent">{d.instructions.recordValue}</span>
                        </div>
                      </div>
                      <button onClick={() => check(d.id)} disabled={busy} className="btn-primary mt-3 disabled:opacity-60">
                        {busy ? 'Kontrol ediliyor…' : 'Doğrulamayı kontrol et'}
                      </button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      )}

      <section className="mt-8">
        {!showAdd ? (
          <div className="flex flex-wrap items-center gap-3">
            <button onClick={() => setShowAdd(true)} className="btn-outline">
              + Yeni alan adı ekle
            </button>
            {!purchaseMode && domains.length > 0 && (
              <button onClick={delAll} className="btn-ghost text-sm text-red-600">
                Tümünü sil
              </button>
            )}
          </div>
        ) : (
          <form onSubmit={addDomain} className="card p-5">
            <label className="label">Yeni alan adı</label>
            <div className="flex flex-col gap-2 sm:flex-row">
              <input
                required
                placeholder="ornek.com"
                className="field flex-1"
                value={newHostname}
                onChange={(e) => setNewHostname(e.target.value)}
              />
              <button type="submit" disabled={busy} className="btn-primary disabled:opacity-60">
                {busy ? 'Ekleniyor…' : 'Ekle ve doğrula'}
              </button>
            </div>
            {(() => {
              const raw = newHostname.trim();
              const host = previewHostname(newHostname);
              // "https://", "www.", sondaki "/" vb. yazıldıysa hangi çıplak alan adının
              // ekleneceğini göster (kafa karışıklığını önler).
              if (host && raw.toLowerCase() !== host) {
                return (
                  <p className="mt-2 text-xs text-ink-muted">
                    Şu alan adı eklenecek: <span className="font-mono font-semibold text-ink">{host}</span>
                    <br />
                    <span className="text-ink-muted">
                      (<code>https://</code>, <code>www.</code> ve yol kısımları otomatik atılır.)
                    </span>
                  </p>
                );
              }
              return null;
            })()}
          </form>
        )}
      </section>

      {domains.length === 0 && !showAdd && (
        <p className="mt-4 text-sm text-ink-muted">
          Henüz alan adın yok. Başlamak için bir alan adı ekleyip doğrula.
        </p>
      )}
    </>
  );

  const orderCard = (o: Order, isArchived: boolean) => (
    // MOBİL: dikey yığ (bilgi üstte, eylemler altta sarar) — aksi halde host + 4 buton yan yana sıkışıp
    // üst üste biniyordu. sm+ : yatay (bilgi solda, eylemler sağda).
    <div key={o.id} className="card flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between">
      <button onClick={() => router.push(`/dashboard/${o.id}`)} className="min-w-0 text-left sm:flex-1">
        <div className="truncate font-semibold text-ink">{o.hostname}</div>
        <div className="mt-0.5 text-xs text-ink-muted">
          {o.packageName} · {new Date(o.createdAt).toLocaleDateString('tr-TR')}
        </div>
      </button>
      <div className="flex flex-wrap items-center gap-2 sm:justify-end sm:shrink-0">
        <span className="badge">{ORDER_STATUS_LABEL[o.status] ?? o.status}</span>
        {/* (Fatura talebi) ödemesi tamamlanmış siparişte talep/durum — form dashboard'ta (#fatura). */}
        {o.paid && (
          <button onClick={() => router.push(`/dashboard/${o.id}#fatura`)} className="btn-ghost text-xs text-accent-700">
            {o.invoiceStatus === 'sent' ? 'Fatura gönderildi' : o.invoiceStatus ? 'Fatura talebi ✓' : 'Fatura talep et'}
          </button>
        )}
        {isArchived ? (
          <button onClick={() => archiveOrder(o.id, false)} className="btn-ghost text-xs">
            Arşivden çıkar
          </button>
        ) : (
          <>
            <button onClick={() => archiveOrder(o.id, true)} className="btn-ghost text-xs">
              Arşivle
            </button>
            <button onClick={() => deleteOrder(o.id)} className="btn-ghost text-xs text-red-600">
              Sil
            </button>
          </>
        )}
      </div>
    </div>
  );

  return (
    <main className="container-page max-w-2xl py-14">
      <div>
        <p className="eyebrow">Panelim</p>
        <h1 className="mt-1 text-2xl font-extrabold text-brand">
          {purchaseMode ? 'Alan adı seçin' : 'Taramaya Başla'}
        </h1>
      </div>

      {loading ? (
        <div className="mt-8 h-32 animate-pulse rounded-card bg-brand-50" />
      ) : purchaseMode ? (
        <>
          {/* SATIN-ALMA MODU: yalnız alan adı seçimi (rapor geçmişi YOK). Paket sonraki adımda hazır gelir. */}
          <div className="mt-6 rounded-card border border-accent/40 bg-accent-soft/40 px-4 py-3 text-sm text-ink-soft">
            Seçtiğiniz paket için bir <strong>alan adı</strong> seçin. Doğrulanmış bir alan adınız varsa tek tıkla
            devam edin; yoksa yeni bir alan adı ekleyip doğrulayın.
          </div>
          {domainSection}
        </>
      ) : (
        <>
          {/* (İŞ 2) SEKME NAVİGASYONU — Taramalarım · Alan Adları · Zamanlanmış (net ayrım). */}
          <nav className="mt-6 flex flex-wrap gap-1.5 border-b border-line">
            {([
              ['history', 'Taramalarım', orders.length],
              ['domains', 'Alan Adları', validDomains.length],
            ] as const).map(([key, label, count]) => (
              <button
                key={key}
                onClick={() => setTab(key)}
                className={`-mb-px rounded-t-card border-b-2 px-3.5 py-2 text-sm font-semibold transition ${
                  tab === key ? 'border-brand text-brand' : 'border-transparent text-ink-muted hover:text-ink'
                }`}
              >
                {label}
                {count > 0 && <span className="ml-1.5 rounded-pill bg-brand-50 px-1.5 py-0.5 text-[10px] font-bold text-brand">{count}</span>}
              </button>
            ))}
            <a
              href="/schedules"
              className="-mb-px rounded-t-card border-b-2 border-transparent px-3.5 py-2 text-sm font-semibold text-ink-muted transition hover:text-ink"
            >
              Zamanlanmış ↗
            </a>
          </nav>

          {tab === 'domains' && domainSection}

          {tab === 'history' && (
            orders.length > 0 ? (
              <section className="mt-6">
                <div className="flex items-center justify-between">
                  <h2 className="text-sm font-bold uppercase tracking-wide text-ink-muted">Taramalarım</h2>
                  <button onClick={toggleArchived} className="text-xs font-medium text-accent-600 hover:underline">
                    {showArchived ? 'Arşivlenenleri gizle' : 'Arşivlenenler'}
                    {archivedOrders && archivedOrders.length > 0 ? ` (${archivedOrders.length})` : ''}
                  </button>
                </div>
                <div className="mt-3 space-y-2.5">{shownHistory.map((o) => orderCard(o, false))}</div>
                {orders.length > HISTORY_PREVIEW && (
                  <button
                    onClick={() => setShowAllHistory((v) => !v)}
                    className="mt-3 text-sm font-medium text-accent-600 hover:underline"
                  >
                    {showAllHistory ? 'Daha az göster' : `Tümünü gör (${orders.length})`}
                  </button>
                )}

                {showArchived && (
                  <div className="mt-6 border-t border-line pt-6">
                    <h3 className="text-xs font-bold uppercase tracking-wide text-ink-muted">Arşivlenenler</h3>
                    {archivedOrders && archivedOrders.length > 0 ? (
                      <div className="mt-2 space-y-2.5">{archivedOrders.map((o) => orderCard(o, true))}</div>
                    ) : (
                      <p className="mt-2 text-sm text-ink-muted">Arşivlenmiş tarama yok.</p>
                    )}
                  </div>
                )}
              </section>
            ) : (
              <p className="mt-8 text-sm text-ink-muted">Henüz bir taramanız yok. “Alan Adları” sekmesinden bir tarama başlatın.</p>
            )
          )}
        </>
      )}

      {error && <p className="form-error mt-6">{error}</p>}
      {notice && (
        <p className="mt-6 rounded-card border border-emerald-300/50 bg-emerald-50/60 px-4 py-3 text-sm text-emerald-800">
          ✓ {notice}
        </p>
      )}
    </main>
  );
}
