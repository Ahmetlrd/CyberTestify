'use client';

import { useCallback, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { api } from '../../lib/api';
import { isActivePackageKey } from '../../lib/packages';
import { readRegionCookie } from '../../lib/region';
import { getRegion, type RegionCode } from '../../config/regions';

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

// (Savunma) awaiting_admin_review backend'de zaten 'scan_running'e maskelenir; yine de hiçbir koşulda
// ham enum sızmasın diye burada da "Taranıyor"/"Wird gescannt" gösterilir.
// (DURUM RENGI) Rozet rengi duruma gore — "hazır" yeşil, bekleyen amber, hata kırmızı, biten gri.
// Yalniz ROZET renklenir; sayfanin geri kalan paleti degismez.
function statusTone(status: string): string {
  if (status === 'scan_completed' || status === 'report_delivered') return 'border-emerald-200 bg-emerald-50 text-emerald-700';
  if (status === 'scan_running' || status === 'scan_queued' || status === 'paid') return 'border-sky-200 bg-sky-50 text-sky-700';
  if (status === 'awaiting_payment' || status === 'awaiting_domain_verification' || status === 'awaiting_admin_review') return 'border-amber-200 bg-amber-50 text-amber-800';
  if (status === 'scan_failed' || status === 'scope_violation') return 'border-red-200 bg-red-50 text-red-700';
  return 'border-line bg-brand-50 text-ink-muted'; // refunded / report_purged / bilinmeyen
}

const ORDER_STATUS_LABEL: Record<'tr' | 'de' | 'en', Record<string, string>> = {
  tr: {
    awaiting_payment: 'Ödeme bekleniyor',
    awaiting_domain_verification: 'Alan adı doğrulaması bekleniyor',
    paid: 'Sıraya alınıyor',
    scan_queued: 'Başlatılıyor',
    scan_running: 'Taranıyor',
    awaiting_admin_review: 'Taranıyor',
    scan_completed: 'Rapor hazır',
    report_delivered: 'Rapor hazır',
    scan_failed: 'Başarısız',
    scope_violation: 'Durduruldu (kapsam dışı)',
    report_purged: 'Süresi doldu',
    refunded: 'İade edildi',
  },
  de: {
    awaiting_payment: 'Zahlung ausstehend',
    awaiting_domain_verification: 'Domain-Verifizierung ausstehend',
    paid: 'Wird eingereiht',
    scan_queued: 'Wird gestartet',
    scan_running: 'Wird gescannt',
    awaiting_admin_review: 'Wird gescannt',
    scan_completed: 'Bericht bereit',
    report_delivered: 'Bericht bereit',
    scan_failed: 'Fehlgeschlagen',
    scope_violation: 'Gestoppt (außerhalb des Geltungsbereichs)',
    report_purged: 'Abgelaufen',
    refunded: 'Erstattet',
  },
  en: {
    awaiting_payment: 'Awaiting payment',
    awaiting_domain_verification: 'Awaiting domain verification',
    paid: 'Queuing',
    scan_queued: 'Starting',
    scan_running: 'Scanning',
    awaiting_admin_review: 'Scanning',
    scan_completed: 'Report ready',
    report_delivered: 'Report ready',
    scan_failed: 'Failed',
    scope_violation: 'Stopped (out of scope)',
    report_purged: 'Expired',
    refunded: 'Refunded',
  },
};

// (Çok-bölge) /verify panel metinleri — /de tamamen Almanca (Sie-Form, „…" tırnak).
const VER_T = {
  tr: {
    verifiedDomains: 'Doğrulanmış alan adların',
    verifiedValid: 'Doğrulandı · geçerli',
    continueWithDomain: 'Bu alan adı ile devam et',
    startScan: 'Taramayı Başlat',
    delete: 'Sil',
    pendingVerification: 'Doğrulama bekleyen',
    expiredReverify: 'Süresi doldu — yeniden doğrula',
    notVerifiedYet: 'Henüz doğrulanmadı',
    passiveHint: 'Pasif paketler için doğrulama gerekmez. Aktif paketler DNS doğrulaması ister.',
    continue: 'Devam et',
    hide: 'Gizle',
    verify: 'Doğrula',
    txtIntro1: 'DNS panelinize aşağıdaki',
    txtIntro2: 'kaydını ekleyin:',
    nameLabel: 'Ad:',
    valueLabel: 'Değer:',
    checking: 'Kontrol ediliyor…',
    checkVerification: 'Doğrulamayı kontrol et',
    addNewDomain: '+ Yeni alan adı ekle',
    deleteAll: 'Tümünü sil',
    newDomain: 'Yeni alan adı',
    adding: 'Ekleniyor…',
    addAndContinue: 'Ekle ve devam et',
    add: 'Ekle',
    domainPlaceholder: 'ornek.com',
    willBeAdded: 'Şu alan adı eklenecek:',
    stripNote1: 've yol kısımları otomatik atılır.',
    noDomains: 'Henüz alan adın yok. Başlamak için bir alan adı ekleyip doğrula.',
    invoiceSent: 'Fatura gönderildi',
    invoiceRequested: 'Fatura talebi ✓',
    requestInvoice: 'Fatura talep et',
    viewReport: 'Raporu aç',
    unarchive: 'Arşivden çıkar',
    archive: 'Arşivle',
    myPanel: 'Panelim',
    selectDomain: 'Alan adı seçin',
    startScanning: 'Taramaya Başla',
    activeNotice1: 'Aktif güvenlik testlerini başlatabilmemiz için alan adının size ait olduğunu',
    activeNoticeStrong: 'DNS TXT kaydıyla',
    activeNotice2: 'doğrulamanız gerekiyor.',
    passiveTitle: 'Bu paket için doğrulama gerekmez',
    passiveBody1: 'Pasif tarama yalnızca dışarıdan gözlem yapar (güvenlik başlıkları, TLS, yapılandırma).',
    passiveBody2: 'Alan adınızı ekleyip',
    passiveBodyStrong: 'hemen devam edebilirsiniz',
    passiveBody3: '— DNS kaydı eklemenize gerek yok.',
    tabMyScans: 'Taramalarım',
    tabDomains: 'Alan Adları',
    tabScheduled: 'Zamanlanmış ↗',
    myScans: 'Taramalarım',
    hideArchived: 'Arşivlenenleri gizle',
    archived: 'Arşivlenenler',
    showLess: 'Daha az göster',
    showAll: (n: number) => `Tümünü gör (${n})`,
    noArchivedScans: 'Arşivlenmiş tarama yok.',
    noScansYet: 'Henüz bir taramanız yok. “Alan Adları” sekmesinden bir tarama başlatın.',
    confirmDeleteDomain: 'Bu alan adını silmek istediğinize emin misiniz? Bu işlem geri alınamaz.',
    confirmDeleteAll: 'Taraması olmayan tüm alan adları silinsin mi?',
    confirmDeleteReport: 'Bu raporu silmek istediğinize emin misiniz? Bu işlem geri alınamaz.',
    dnsNotVisible: 'Kayıt henüz görünmüyor. DNS yayılımı biraz sürebilir; birazdan tekrar deneyin.',
    alreadyVerified: (h: string) => `“${h}” zaten ekli ve doğrulanmış.`,
    bulkDeleted: (d: number, k: number) => `${d} alan adı silindi; taraması olan ${k} tanesi korundu.`,
  },
  de: {
    verifiedDomains: 'Ihre verifizierten Domains',
    verifiedValid: 'Verifiziert · gültig',
    continueWithDomain: 'Mit dieser Domain fortfahren',
    startScan: 'Scan starten',
    delete: 'Löschen',
    pendingVerification: 'Verifizierung ausstehend',
    expiredReverify: 'Abgelaufen — erneut verifizieren',
    notVerifiedYet: 'Noch nicht verifiziert',
    passiveHint: 'Für passive Pakete ist keine Verifizierung erforderlich. Aktive Pakete erfordern eine DNS-Verifizierung.',
    continue: 'Fortfahren',
    hide: 'Ausblenden',
    verify: 'Verifizieren',
    txtIntro1: 'Fügen Sie in Ihrem DNS-Panel den folgenden',
    txtIntro2: 'Eintrag hinzu:',
    nameLabel: 'Name:',
    valueLabel: 'Wert:',
    checking: 'Wird geprüft…',
    checkVerification: 'Verifizierung prüfen',
    addNewDomain: '+ Neue Domain hinzufügen',
    deleteAll: 'Alle löschen',
    newDomain: 'Neue Domain',
    adding: 'Wird hinzugefügt…',
    addAndContinue: 'Hinzufügen und fortfahren',
    add: 'Hinzufügen',
    domainPlaceholder: 'beispiel.de',
    willBeAdded: 'Folgende Domain wird hinzugefügt:',
    stripNote1: 'und Pfadangaben werden automatisch entfernt.',
    noDomains: 'Sie haben noch keine Domain. Fügen Sie eine Domain hinzu und verifizieren Sie sie, um zu beginnen.',
    invoiceSent: 'Rechnung gesendet',
    invoiceRequested: 'Rechnung angefordert ✓',
    requestInvoice: 'Rechnung anfordern',
    viewReport: 'Bericht öffnen',
    unarchive: 'Aus Archiv entfernen',
    archive: 'Archivieren',
    myPanel: 'Mein Bereich',
    selectDomain: 'Domain auswählen',
    startScanning: 'Scan starten',
    activeNotice1: 'Damit wir aktive Sicherheitstests starten können, müssen Sie mit einem',
    activeNoticeStrong: 'DNS-TXT-Eintrag',
    activeNotice2: 'nachweisen, dass die Domain Ihnen gehört.',
    passiveTitle: 'Für dieses Paket ist keine Verifizierung erforderlich',
    passiveBody1: 'Der passive Scan beobachtet nur von außen (Sicherheitsheader, TLS, Konfiguration).',
    passiveBody2: 'Fügen Sie Ihre Domain hinzu und',
    passiveBodyStrong: 'fahren Sie sofort fort',
    passiveBody3: '— Sie müssen keinen DNS-Eintrag hinzufügen.',
    tabMyScans: 'Meine Scans',
    tabDomains: 'Domains',
    tabScheduled: 'Geplant ↗',
    myScans: 'Meine Scans',
    hideArchived: 'Archivierte ausblenden',
    archived: 'Archivierte',
    showLess: 'Weniger anzeigen',
    showAll: (n: number) => `Alle anzeigen (${n})`,
    noArchivedScans: 'Keine archivierten Scans.',
    noScansYet: 'Sie haben noch keine Scans. Starten Sie einen Scan über den Tab „Domains“.',
    confirmDeleteDomain: 'Möchten Sie diese Domain wirklich löschen? Dieser Vorgang kann nicht rückgängig gemacht werden.',
    confirmDeleteAll: 'Sollen alle Domains ohne Scans gelöscht werden?',
    confirmDeleteReport: 'Möchten Sie diesen Bericht wirklich löschen? Dieser Vorgang kann nicht rückgängig gemacht werden.',
    dnsNotVisible: 'Der Eintrag ist noch nicht sichtbar. Die DNS-Verbreitung kann etwas dauern; bitte versuchen Sie es gleich erneut.',
    alreadyVerified: (h: string) => `„${h}“ ist bereits hinzugefügt und verifiziert.`,
    bulkDeleted: (d: number, k: number) => `${d} Domain(s) gelöscht; ${k} mit Scans wurden beibehalten.`,
  },
  en: {
    verifiedDomains: 'Your verified domains',
    verifiedValid: 'Verified · valid',
    continueWithDomain: 'Continue with this domain',
    startScan: 'Start scan',
    delete: 'Delete',
    pendingVerification: 'Awaiting verification',
    expiredReverify: 'Expired — re-verify',
    notVerifiedYet: 'Not verified yet',
    passiveHint: 'Passive packages require no verification. Active packages require DNS verification.',
    continue: 'Continue',
    hide: 'Hide',
    verify: 'Verify',
    txtIntro1: 'Add the following',
    txtIntro2: 'record to your DNS panel:',
    nameLabel: 'Name:',
    valueLabel: 'Value:',
    checking: 'Checking…',
    checkVerification: 'Check verification',
    addNewDomain: '+ Add new domain',
    deleteAll: 'Delete all',
    newDomain: 'New domain',
    adding: 'Adding…',
    addAndContinue: 'Add and continue',
    add: 'Add',
    domainPlaceholder: 'example.com',
    willBeAdded: 'The following domain will be added:',
    stripNote1: 'and path segments are removed automatically.',
    noDomains: 'You don\'t have any domains yet. Add a domain and verify it to get started.',
    invoiceSent: 'Invoice sent',
    invoiceRequested: 'Invoice requested ✓',
    requestInvoice: 'Request invoice',
    viewReport: 'Open report',
    unarchive: 'Unarchive',
    archive: 'Archive',
    myPanel: 'My dashboard',
    selectDomain: 'Select a domain',
    startScanning: 'Start scanning',
    activeNotice1: 'Before we can start active security tests, you need to prove the domain belongs to you with a',
    activeNoticeStrong: 'DNS TXT record',
    activeNotice2: '.',
    passiveTitle: 'No verification is required for this package',
    passiveBody1: 'The passive scan only observes from the outside (security headers, TLS, configuration).',
    passiveBody2: 'Add your domain and',
    passiveBodyStrong: 'continue right away',
    passiveBody3: '— no need to add a DNS record.',
    tabMyScans: 'My scans',
    tabDomains: 'Domains',
    tabScheduled: 'Scheduled ↗',
    myScans: 'My scans',
    hideArchived: 'Hide archived',
    archived: 'Archived',
    showLess: 'Show less',
    showAll: (n: number) => `Show all (${n})`,
    noArchivedScans: 'No archived scans.',
    noScansYet: 'You don\'t have any scans yet. Start a scan from the “Domains” tab.',
    confirmDeleteDomain: 'Are you sure you want to delete this domain? This action cannot be undone.',
    confirmDeleteAll: 'Delete all domains without scans?',
    confirmDeleteReport: 'Are you sure you want to delete this report? This action cannot be undone.',
    dnsNotVisible: 'The record is not visible yet. DNS propagation can take a little while; please try again shortly.',
    alreadyVerified: (h: string) => `“${h}” is already added and verified.`,
    bulkDeleted: (d: number, k: number) => `${d} domain(s) deleted; ${k} with scans were kept.`,
  },
} as const;

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
  // (İş 2 — autopopulate) Teaser'dan taşınan alan adı: form otomatik dolu gelsin.
  const hostnameParam = params.get('hostname');
  // (Kullanıcı isteği) /order'daki "Doğrula" CTA'sı belirli bir alan adının DNS paneline odaklanmak
  // için domainId taşır: o alan adının doğrulama panelini AÇ + üstüne kaydır.
  const focusDomainId = params.get('domainId');
  const purchaseMode = !!(packageParam || bundleParam);
  // (PASİF/AKTİF AYRIMI) Aktif paketlerde DNS doğrulaması ZORUNLU; pasiflerde doğrulama gerekmez.
  const activePurchase = isActivePackageKey(packageParam) || isActivePackageKey(bundleParam);
  const purchaseQuery = packageParam ? `&package=${packageParam}` : bundleParam ? `&bundle=${bundleParam}` : '';

  const [domains, setDomains] = useState<Domain[]>([]);
  const [orders, setOrders] = useState<Order[]>([]);
  const [archivedOrders, setArchivedOrders] = useState<Order[] | null>(null);
  const [showAllHistory, setShowAllHistory] = useState(false);
  const [showArchived, setShowArchived] = useState(false);
  const [loading, setLoading] = useState(true);
  const [newHostname, setNewHostname] = useState('');
  const [openId, setOpenId] = useState<string | null>(null);
  const [checkMsg, setCheckMsg] = useState<string | null>(null); // DNS kontrol sonucu — panel içinde, butonun altında
  // (UYARILARI GÖRÜNÜR KIL) Aksiyon hataları sayfanın en altında kalıp gözden kaçıyordu; her mesajı
  // ilgili butonun/kartın HEMEN ALTINDA göster.
  const [domainMsg, setDomainMsg] = useState<{ id: string; text: string } | null>(null); // alan adı kartı (sil vb.)
  const [orderMsg, setOrderMsg] = useState<{ id: string; text: string } | null>(null); // tarama kartı (sil/arşiv)
  const [bulkMsg, setBulkMsg] = useState<string | null>(null); // ekle-formu / toplu-sil bölgesi
  const [busy, setBusy] = useState(false);
  const [showAdd, setShowAdd] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  // (İŞ 2) Panel sekmeleri — dağınık iç içe bölümler yerine net ayrım.
  const [tab, setTab] = useState<'domains' | 'history'>('domains');
  // (Çok-bölge) Dil + locale: region cookie'sinden. de → Almanca metin + Alman tarih biçimi.
  const [region, setRegion] = useState<RegionCode>('tr');
  const lang: 'tr' | 'de' | 'en' = getRegion(region).lang === 'de' ? 'de' : getRegion(region).lang === 'en' ? 'en' : 'tr';
  const T = VER_T[lang];
  const dateLocale = getRegion(region).locale;

  const refresh = useCallback(async () => {
    const [list, ord] = await Promise.all([api.listDomains(), api.listOrders(false)]);
    setDomains(list);
    setOrders(ord as Order[]);
    if (showArchived) setArchivedOrders((await api.listOrders(true)) as Order[]);
    return list;
  }, [showArchived]);

  useEffect(() => {
    setRegion(readRegionCookie());
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

  // (İş 2) Teaser'dan gelen alan adını ekleme formuna otomatik doldur + formu aç (kullanıcı yazmasın).
  useEffect(() => {
    if (hostnameParam) {
      setNewHostname(hostnameParam);
      setShowAdd(true);
    }
  }, [hostnameParam]);

  // (Odak) /order'dan domainId ile gelindiyse: o alan adının doğrulama panelini AÇ + üstüne kaydır.
  const [focused, setFocused] = useState(false);
  useEffect(() => {
    if (!focusDomainId || focused) return;
    if (domains.some((d) => d.id === focusDomainId)) {
      setOpenId(focusDomainId);
      setFocused(true);
      setTimeout(() => document.getElementById(`domain-${focusDomainId}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 120);
    }
  }, [domains, focusDomainId, focused]);

  async function addDomain(e: React.FormEvent) {
    e.preventDefault();
    if (!newHostname.trim() || busy) return;
    setBusy(true);
    setBulkMsg(null);
    setNotice(null);
    try {
      const res = await api.createDomain(newHostname.trim());
      setNewHostname('');
      setShowAdd(false);
      // (PASİF paket satın-alma) DNS doğrulaması GEREKMEZ → alan adı eklenince doğrudan sipariş
      // adımına geç (sürtünmesiz). Aktif paketlerde bu atlama YOK; DNS TXT akışı zorunlu.
      if (purchaseMode && !activePurchase) {
        goToOrder(res.domainId);
        return;
      }
      await refresh();
      setOpenId(res.domainId);
      // Zaten ekli + doğrulanmışsa: onaylı kayıt KORUNUR (yeniden DNS doğrulama yok) + net bilgi.
      if (res.alreadyVerified) setNotice(res.message || T.alreadyVerified(res.hostname));
    } catch (e: any) {
      setBulkMsg(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function check(id: string) {
    setBusy(true);
    setError(null);
    setCheckMsg(null); // önceki sonucu temizle (mesaj butonun ALTINDA, panel içinde gösterilir)
    try {
      const { verified } = await api.verifyDomain(id);
      await refresh();
      if (verified) goToOrder(id);
      else setCheckMsg(T.dnsNotVisible);
    } catch (e: any) {
      setCheckMsg(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function del(id: string) {
    if (!window.confirm(T.confirmDeleteDomain)) return;
    setDomainMsg(null);
    try {
      await api.deleteDomain(id);
      await refresh();
    } catch (e: any) {
      setDomainMsg({ id, text: e.message }); // uyarı ilgili alan adı kartının altında görünür
    }
  }

  async function delAll() {
    if (!window.confirm(T.confirmDeleteAll)) return;
    setBulkMsg(null);
    try {
      const r = await api.deleteAllDomains();
      await refresh();
      if (r.kept > 0) setBulkMsg(T.bulkDeleted(r.deleted, r.kept));
    } catch (e: any) {
      setBulkMsg(e.message);
    }
  }

  async function archiveOrder(id: string, archived: boolean) {
    setOrderMsg(null);
    try {
      await api.archiveOrder(id, archived);
      await refresh();
    } catch (e: any) {
      setOrderMsg({ id, text: e.message });
    }
  }

  async function deleteOrder(id: string) {
    if (!window.confirm(T.confirmDeleteReport)) return;
    setOrderMsg(null);
    try {
      await api.deleteOrder(id);
      await refresh();
    } catch (e: any) {
      setOrderMsg({ id, text: e.message });
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
          <h2 className="text-sm font-bold uppercase tracking-wide text-ink-muted">{T.verifiedDomains}</h2>
          <div className="mt-3 space-y-2.5">
            {validDomains.map((d) => (
              <div key={d.id} className="card p-4">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div className="min-w-0">
                    <div className="truncate font-semibold text-ink">{d.hostname}</div>
                    <span className="mt-0.5 inline-flex items-center gap-1 text-xs font-medium text-emerald-600">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" /> {T.verifiedValid}
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-2 sm:shrink-0">
                    <button onClick={() => goToOrder(d.id)} className="btn-primary">
                      {purchaseMode ? T.continueWithDomain : T.startScan}
                    </button>
                    {!purchaseMode && (
                      <button onClick={() => del(d.id)} className="btn-ghost text-sm text-red-600">
                        {T.delete}
                      </button>
                    )}
                  </div>
                </div>
                {domainMsg?.id === d.id && (
                  <p className="mt-3 rounded-card border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{domainMsg.text}</p>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {pendingDomains.length > 0 && (
        <section className="mt-8">
          <h2 className="text-sm font-bold uppercase tracking-wide text-ink-muted">{T.pendingVerification}</h2>
          <div className="mt-3 space-y-2.5">
            {pendingDomains.map((d) => {
              const expired = d.status === 'verified' && !d.valid;
              const open = openId === d.id;
              return (
                <div key={d.id} id={`domain-${d.id}`} className="card p-4">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <div className="min-w-0">
                      <div className="truncate font-semibold text-ink">{d.hostname}</div>
                      <span className={`mt-0.5 block text-xs font-medium ${expired ? 'text-red-600' : 'text-amber-600'}`}>
                        {expired ? T.expiredReverify : T.notVerifiedYet}
                      </span>
                      {!purchaseMode && (
                        <span className="mt-0.5 block text-[11px] text-ink-muted">
                          {T.passiveHint}
                        </span>
                      )}
                    </div>
                    <div className="flex flex-wrap items-center gap-2 sm:shrink-0">
                      {/* PASİF satın-alma: doğrulama gerekmez → tek tıkla devam. Aktifte bu buton YOK. */}
                      {purchaseMode && !activePurchase && (
                        <button onClick={() => goToOrder(d.id)} className="btn-primary text-sm">
                          {T.continue}
                        </button>
                      )}
                      {/* NORMAL panel: doğrulanmamış alan adı için de "Taramayı Başlat" — pasif 4 paket
                          doğrulama gerektirmez. Aktif paket seçilirse /order doğrulamaya yönlendirir. */}
                      {!purchaseMode && (
                        <button onClick={() => goToOrder(d.id)} className="btn-primary text-sm">
                          {T.startScan}
                        </button>
                      )}
                      <button onClick={() => { setCheckMsg(null); setOpenId(open ? null : d.id); }} className="btn-outline text-sm">
                        {open ? T.hide : T.verify}
                      </button>
                      <button onClick={() => del(d.id)} className="btn-ghost text-sm text-red-600">
                        {T.delete}
                      </button>
                    </div>
                  </div>
                  {open && (
                    <div className="mt-4 border-t border-line pt-4">
                      <p className="text-sm text-ink-soft">{T.txtIntro1} <strong>TXT</strong> {T.txtIntro2}</p>
                      <div className="mt-2 space-y-2 rounded-card bg-brand-deep p-3.5 font-mono text-xs text-white/90">
                        <div>
                          <span className="text-white/45">{T.nameLabel}</span>{' '}
                          <span className="break-all text-emerald-300">{d.instructions.recordName}</span>
                        </div>
                        <div>
                          <span className="text-white/45">{T.valueLabel}</span>{' '}
                          <span className="break-all text-accent">{d.instructions.recordValue}</span>
                        </div>
                      </div>
                      <button onClick={() => check(d.id)} disabled={busy} className="btn-primary mt-3 disabled:opacity-60">
                        {busy ? T.checking : T.checkVerification}
                      </button>
                      {checkMsg && (
                        <p className="mt-2 rounded-card border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-800">
                          {checkMsg}
                        </p>
                      )}
                    </div>
                  )}
                  {domainMsg?.id === d.id && (
                    <p className="mt-3 rounded-card border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{domainMsg.text}</p>
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
              {T.addNewDomain}
            </button>
            {!purchaseMode && domains.length > 0 && (
              <button onClick={delAll} className="btn-ghost text-sm text-red-600">
                {T.deleteAll}
              </button>
            )}
          </div>
        ) : (
          <form onSubmit={addDomain} className="card max-w-2xl p-5">
            <label className="label">{T.newDomain}</label>
            <div className="flex flex-col gap-2 sm:flex-row">
              <input
                required
                placeholder={T.domainPlaceholder}
                className="field flex-1"
                value={newHostname}
                onChange={(e) => setNewHostname(e.target.value)}
              />
              <button type="submit" disabled={busy} className="btn-primary disabled:opacity-60">
                {busy ? T.adding : purchaseMode && !activePurchase ? T.addAndContinue : T.add}
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
                    {T.willBeAdded} <span className="font-mono font-semibold text-ink">{host}</span>
                    <br />
                    <span className="text-ink-muted">
                      (<code>https://</code>, <code>www.</code> {T.stripNote1})
                    </span>
                  </p>
                );
              }
              return null;
            })()}
          </form>
        )}
        {/* Ekle / toplu-sil sonucu — bölümün HEMEN ALTINDA (sayfa sonunda değil). */}
        {bulkMsg && (
          <p className="mt-3 rounded-card border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-800">{bulkMsg}</p>
        )}
        {notice && (
          <p className="mt-3 rounded-card border border-emerald-300/50 bg-emerald-50/60 px-3 py-2 text-sm text-emerald-800">✓ {notice}</p>
        )}
      </section>

      {domains.length === 0 && !showAdd && (
        <p className="mt-4 text-sm text-ink-muted">
          {T.noDomains}
        </p>
      )}
    </>
  );

  const orderCard = (o: Order, isArchived: boolean) => (
    // (FORMAT) Her sipariş AYRI kart değil; tek kart içinde ayraçlı SATIR (sıkışıklık gider, nefes alır).
    // Kilit ikonu + alan adı + "Raporu aç" ÜÇÜ DE aynı yere (rapor sayfası) gider.
    // MOBİL: dikey yığ; sm+ : yatay (bilgi solda, eylemler sağda). RENKLER DEĞİŞMEDİ.
    <div key={o.id} className="px-5 py-4">
      {/* (DUZELTME) Once sag taraf sm:shrink-0 idi ve sol sutunu eziyordu (alan adi "g.." gibi
          kirpiliyordu). Grid ile sol sutuna EN AZ 200px garanti edildi; sag taraf gerekirse sarar. */}
      <div className="flex flex-col gap-3 sm:grid sm:grid-cols-[minmax(300px,1fr)_auto] sm:items-center sm:gap-5">
        <button
          onClick={() => router.push(`/dashboard/${o.id}`)}
          className="group flex min-w-0 items-center gap-3.5 text-left"
        >
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-brand-50 transition group-hover:bg-brand-100">
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" className="text-brand" aria-hidden>
              <rect x="5" y="10.5" width="14" height="9.5" rx="2" />
              <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
            </svg>
          </span>
          <span className="min-w-0">
            <span className="block truncate font-mono text-[15px] font-semibold text-ink group-hover:text-brand">{o.hostname}</span>
            <span className="mt-0.5 block truncate text-xs text-ink-muted">
              {o.packageName} · {new Date(o.createdAt).toLocaleDateString(dateLocale)}
            </span>
          </span>
        </button>
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1.5 sm:flex-nowrap sm:justify-end">
          <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-pill border px-2.5 py-1 text-xs font-semibold ${statusTone(o.status)}`}>
            <span aria-hidden className="h-1.5 w-1.5 shrink-0 rounded-full bg-current" />
            {ORDER_STATUS_LABEL[lang][o.status] ?? o.status}
          </span>
          {/* (UX) Rapor hazırsa: rozet TEK BAŞINA tıklanabilir görünmüyordu; net bir CTA butonu
              ekleniyor. Erişim akışı (kod/doğrulama) DEĞİŞMEZ — sadece görünür/tıklanabilir hedef. */}
          {(o.status === 'scan_completed' || o.status === 'report_delivered') && (
            <button
              onClick={() => router.push(`/dashboard/${o.id}`)}
              className="rounded-pill bg-accent px-5 py-2 text-xs font-bold text-ink shadow-sm transition hover:bg-accent-hover"
            >
              {T.viewReport}
            </button>
          )}
          {/* (Fatura talebi) ödemesi tamamlanmış siparişte talep/durum — form dashboard'ta (#fatura). */}
          {o.paid && (
            <button onClick={() => router.push(`/dashboard/${o.id}#fatura`)} className="whitespace-nowrap px-2 py-1 text-xs font-medium text-ink-muted transition hover:text-brand">
              {o.invoiceStatus === 'sent' ? T.invoiceSent : o.invoiceStatus ? T.invoiceRequested : T.requestInvoice}
            </button>
          )}
          {isArchived ? (
            <button onClick={() => archiveOrder(o.id, false)} className="whitespace-nowrap px-2 py-1 text-xs font-medium text-ink-muted transition hover:text-brand">
              {T.unarchive}
            </button>
          ) : (
            <>
              <button onClick={() => archiveOrder(o.id, true)} className="whitespace-nowrap px-2 py-1 text-xs font-medium text-ink-muted transition hover:text-brand">
                {T.archive}
              </button>
              <button onClick={() => deleteOrder(o.id)} className="whitespace-nowrap px-2 py-1 text-xs font-medium text-red-600 transition hover:text-red-700">
                {T.delete}
              </button>
            </>
          )}
        </div>
      </div>
      {orderMsg?.id === o.id && (
        <p className="mt-3 rounded-card border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{orderMsg.text}</p>
      )}
    </div>
  );

  return (
    <main className="container-page max-w-5xl py-14">
      <div>
        <p className="eyebrow">{T.myPanel}</p>
        <h1 className="mt-1 text-2xl font-extrabold text-brand">
          {purchaseMode ? T.selectDomain : T.startScanning}
        </h1>
      </div>

      {/* Sayfa-yükleme / genel hata — başlığın hemen altında (görünür), en altta değil. */}
      {error && <p className="form-error mt-4">{error}</p>}

      {loading ? (
        <div className="mt-8 h-32 animate-pulse rounded-card bg-brand-50" />
      ) : purchaseMode ? (
        <>
          {/* SATIN-ALMA MODU: yalnız alan adı seçimi (rapor geçmişi YOK). Paket sonraki adımda hazır gelir. */}
          {activePurchase ? (
            /* AKTİF paket — DNS doğrulaması ZORUNLU (çelik kapı / yasal). */
            <div className="mt-6 rounded-card border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900/90">
              <p className="leading-relaxed">
                {T.activeNotice1} <strong>{T.activeNoticeStrong}</strong> {T.activeNotice2}
              </p>
            </div>
          ) : (
            /* PASİF paket — doğrulama gerekmez, sürtünmesiz. */
            <div className="mt-6 rounded-card border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900/90">
              <p className="font-bold text-emerald-900">{T.passiveTitle}</p>
              <p className="mt-1 leading-relaxed">
                {T.passiveBody1}{' '}
                {T.passiveBody2} <strong>{T.passiveBodyStrong}</strong> {T.passiveBody3}
              </p>
            </div>
          )}
          {domainSection}
        </>
      ) : (
        <>
          {/* (İŞ 2) SEKME NAVİGASYONU — Taramalarım · Alan Adları · Zamanlanmış (net ayrım). */}
          <nav className="mt-6 flex flex-wrap gap-1.5 border-b border-line">
            {([
              ['history', T.tabMyScans, orders.length],
              ['domains', T.tabDomains, validDomains.length],
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
              {T.tabScheduled}
            </a>
          </nav>

          {tab === 'domains' && domainSection}

          {tab === 'history' && (
            orders.length > 0 ? (
              <section className="mt-6">
                <div className="flex items-center justify-between">
                  <h2 className="text-sm font-bold uppercase tracking-wide text-ink-muted">{T.myScans}</h2>
                  <button onClick={toggleArchived} className="text-xs font-medium text-accent-600 hover:underline">
                    {showArchived ? T.hideArchived : T.archived}
                    {archivedOrders && archivedOrders.length > 0 ? ` (${archivedOrders.length})` : ''}
                  </button>
                </div>
                {/* (FORMAT) Tek kart + satır ayraçları; "Tümünü gör" kartın alt şeridi olarak içeride. */}
                <div className="card mt-3 divide-y divide-line overflow-hidden">
                  {shownHistory.map((o) => orderCard(o, false))}
                  {orders.length > HISTORY_PREVIEW && (
                    <button
                      onClick={() => setShowAllHistory((v) => !v)}
                      className="w-full px-5 py-3.5 text-left text-sm font-semibold text-accent-600 transition hover:bg-brand-50/50"
                    >
                      {showAllHistory ? T.showLess : `${T.showAll(orders.length)} →`}
                    </button>
                  )}
                </div>

                {showArchived && (
                  <div className="mt-6 border-t border-line pt-6">
                    <h3 className="text-xs font-bold uppercase tracking-wide text-ink-muted">{T.archived}</h3>
                    {archivedOrders && archivedOrders.length > 0 ? (
                      <div className="card mt-2 divide-y divide-line overflow-hidden">{archivedOrders.map((o) => orderCard(o, true))}</div>
                    ) : (
                      <p className="mt-2 text-sm text-ink-muted">{T.noArchivedScans}</p>
                    )}
                  </div>
                )}
              </section>
            ) : (
              <p className="mt-8 text-sm text-ink-muted">{T.noScansYet}</p>
            )
          )}
        </>
      )}
    </main>
  );
}
