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
    heroSub: 'Doğrulanmış alan adlarından birini seç ya da yeni bir alan adı ekle. Sonuçlar dakikalar içinde hazır olur.',
    online: 'Hesabınız aktif',
    statDomains: 'doğrulanmış alan adı',
    statScans: 'tarama',
    statPending: 'doğrulama bekliyor',
    schedTitle: 'Zamanlanmış taramalar',
    schedDesc: 'Taramalarını otomatik tekrarla — haftalık, günlük ya da aylık.',
    schedManage: 'Planları yönet',
    addEyebrow: 'YENİ ALAN ADI',
    addTitle: 'Alan adı ekle ve doğrula',
    addDesc: 'DNS kaydı ya da HTML dosyasıyla sahipliği dakikalar içinde doğrula.',
    star: 'Yıldızla', unstar: 'Yıldızı kaldır',
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
    tabAdd: 'Ekle',
    tabScheduled: 'Zamanlanmış ↗',
    myScans: 'Taramalarım',
    hideArchived: 'Arşivlenenleri gizle',
    archived: 'Arşivlenenler',
    showLess: 'Daha az göster',
    showAll: (n: number) => `Tümünü gör (${n})`,
    noArchivedScans: 'Arşivlenmiş tarama yok.',
    noScansYet: 'Henüz bir taramanız yok. “Alan Adları” sekmesinden bir tarama başlatın.',
    confirmArchive: 'Bu taramayı arşivlemek istediğinize emin misiniz?',
    scanSearch: 'Taramalarda ara (alan adı / paket)…',
    noScanMatch: 'Aramanızla eşleşen tarama yok.',
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
    heroSub: 'Wählen Sie eine Ihrer verifizierten Domains oder fügen Sie eine neue hinzu. Ergebnisse sind in wenigen Minuten fertig.',
    online: 'Konto aktiv',
    statDomains: 'verifizierte Domains',
    statScans: 'Scans',
    statPending: 'zu verifizieren',
    schedTitle: 'Geplante Scans',
    schedDesc: 'Wiederholen Sie Scans automatisch — wöchentlich, täglich oder monatlich.',
    schedManage: 'Pläne verwalten',
    addEyebrow: 'NEUE DOMAIN',
    addTitle: 'Domain hinzufügen & verifizieren',
    addDesc: 'Bestätigen Sie den Besitz in Minuten per DNS-Eintrag oder HTML-Datei.',
    star: 'Markieren', unstar: 'Markierung entfernen',
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
    tabAdd: 'Hinzufügen',
    tabScheduled: 'Geplant ↗',
    myScans: 'Meine Scans',
    hideArchived: 'Archivierte ausblenden',
    archived: 'Archivierte',
    showLess: 'Weniger anzeigen',
    showAll: (n: number) => `Alle anzeigen (${n})`,
    noArchivedScans: 'Keine archivierten Scans.',
    noScansYet: 'Sie haben noch keine Scans. Starten Sie einen Scan über den Tab „Domains“.',
    confirmArchive: 'Möchten Sie diesen Scan wirklich archivieren?',
    scanSearch: 'Scans durchsuchen (Domain / Paket)…',
    noScanMatch: 'Keine Scans für Ihre Suche gefunden.',
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
    heroSub: 'Pick one of your verified domains or add a new one. Results are ready within minutes.',
    online: 'Account active',
    statDomains: 'verified domains',
    statScans: 'scans',
    statPending: 'to verify',
    schedTitle: 'Scheduled scans',
    schedDesc: 'Repeat your scans automatically — weekly, daily or monthly.',
    schedManage: 'Manage plans',
    addEyebrow: 'NEW DOMAIN',
    addTitle: 'Add & verify a domain',
    addDesc: 'Verify ownership in minutes via a DNS record or HTML file.',
    star: 'Star', unstar: 'Unstar',
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
    tabAdd: 'Add',
    tabScheduled: 'Scheduled ↗',
    myScans: 'My scans',
    hideArchived: 'Hide archived',
    archived: 'Archived',
    showLess: 'Show less',
    showAll: (n: number) => `Show all (${n})`,
    noArchivedScans: 'No archived scans.',
    noScansYet: 'You don\'t have any scans yet. Start a scan from the “Domains” tab.',
    confirmArchive: 'Are you sure you want to archive this scan?',
    scanSearch: 'Search scans (domain / package)…',
    noScanMatch: 'No scans match your search.',
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
// (Türkçe alan adı düzeltmesi — backend foldTurkishDomainChars ile AYNI) Türkçe/BÜYÜK harfle yazılan
// marka alan adlarını ASCII'ye katla (İ/ı→i, ş→s, ç→c, ğ→g, ö→o, ü→u): "İpekbilgisayar"→"ipekbilgisayar",
// "meşe"→"mese". Türkçe-DIŞI karakterler dokunulmaz (aşağıda punycode korur). toLowerCase'ten ÖNCE.
const TR_ASCII: Record<string, string> = { 'ç':'c','Ç':'c','ğ':'g','Ğ':'g','ı':'i','İ':'i','ö':'o','Ö':'o','ş':'s','Ş':'s','ü':'u','Ü':'u' };
function foldTurkishDomainChars(h: string): string { return h.replace(/[çÇğĞıİöÖşŞüÜ]/g, (c) => TR_ASCII[c] ?? c); }

// backend'de normalizeHostname ile tekrar yapılır — bu yalnız önizleme/UX.)
function previewHostname(input: string): string {
  return foldTurkishDomainChars((input ?? '').trim())
    .toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
    .replace(/^[^/@]*@/, '')
    .replace(/[/?#].*$/, '')
    .replace(/:\d+$/, '')
    .replace(/^www\./, '')
    .replace(/\.+$/, '');
}

// (IDN) Türkçe/uluslararası karakterli alan adı girildiyse punycode'a çevir — backend'le AYNI sonuç
// gösterilsin (ör. şirket.com.tr → xn--...). ASCII girdi değişmez.
function toBareHost(input: string): string {
  const h = previewHostname(input);
  if (/[^\x00-\x7f]/.test(h)) { try { return new URL('http://' + h).hostname; } catch { return h; } }
  return h;
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
  const [scanQuery, setScanQuery] = useState(''); // Taramalarım araması (alan adı / paket)
  const [bulkMsg, setBulkMsg] = useState<string | null>(null); // ekle-formu / toplu-sil bölgesi
  const [busy, setBusy] = useState(false);
  const [showAdd, setShowAdd] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  // (İŞ 2) Panel sekmeleri — dağınık iç içe bölümler yerine net ayrım.
  const [tab, setTab] = useState<'domains' | 'history' | 'add'>('domains');
  const [starred, setStarred] = useState<Set<string>>(new Set());
  useEffect(() => { try { const r = window.localStorage.getItem('ct_starred_domains'); if (r) setStarred(new Set(JSON.parse(r))); } catch { /* noop */ } }, []);
  const toggleStar = (id: string) => setStarred((prev) => {
    const next = new Set(prev);
    if (next.has(id)) next.delete(id); else next.add(id);
    try { window.localStorage.setItem('ct_starred_domains', JSON.stringify([...next])); } catch { /* noop */ }
    return next;
  });
  // (Çok-bölge) Dil + locale: region cookie'sinden. de → Almanca metin + Alman tarih biçimi.
  const [region, setRegion] = useState<RegionCode>('tr');
  const lang: 'tr' | 'de' | 'en' = getRegion(region).lang === 'de' ? 'de' : getRegion(region).lang === 'en' ? 'en' : 'tr';
  const T = VER_T[lang];
  const CHIP_TONE: Record<string, string> = {
    emerald: 'border-emerald-300/30 bg-emerald-400/15 hover:bg-emerald-400/25 text-emerald-50',
    sky: 'border-sky-300/30 bg-sky-400/15 hover:bg-sky-400/25 text-sky-50',
    amber: 'border-amber-300/40 bg-amber-400/20 hover:bg-amber-400/30 text-amber-50',
  };
  const CHIP_NUM: Record<string, string> = { emerald: 'text-emerald-300', sky: 'text-sky-300', amber: 'text-amber-300' };
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
    if (archived && !window.confirm(T.confirmArchive)) return;
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

  const validDomains = domains.filter((d) => d.valid).sort((a, b) => Number(starred.has(b.id)) - Number(starred.has(a.id)));
  const pendingDomains = domains.filter((d) => !d.valid).sort((a, b) => Number(starred.has(b.id)) - Number(starred.has(a.id)));
  const scanMatches = scanQuery.trim()
    ? orders.filter((o) => `${o.hostname} ${o.packageName}`.toLowerCase().includes(scanQuery.trim().toLowerCase()))
    : orders;
  const shownHistory = showAllHistory || scanQuery.trim() ? scanMatches : scanMatches.slice(0, HISTORY_PREVIEW);
  // (Hero özet çipleri) tıklayınca ilgili sekmeye geç + o bölüme yumuşak kaydır.
  const goToSection = (target: 'domains' | 'history', id: string) => {
    setTab(target);
    setTimeout(() => document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 80);
  };
  const starBtn = (id: string) => {
    const on = starred.has(id);
    return (
      <button type="button" onClick={() => toggleStar(id)} title={on ? T.unstar : T.star} aria-label={on ? T.unstar : T.star}
        className={`shrink-0 transition ${on ? 'text-accent' : 'text-ink-muted hover:text-accent'}`}>
        <svg width="17" height="17" viewBox="0 0 24 24" fill={on ? 'currentColor' : 'none'} stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" /></svg>
      </button>
    );
  };

  // --- Alan adı seçim/ekleme bölümü (hem normal hem satın-alma modunda kullanılır) ---
  const addDomainBlock = (
    <form onSubmit={addDomain} className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-brand to-brand-deep p-4 text-white shadow-card sm:p-6">
      <div className="relative">
        <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-accent">{T.addEyebrow}</p>
        <p className="mt-1.5 text-lg font-bold">{T.addTitle}</p>
        <p className="mt-1 hidden max-w-md text-sm leading-relaxed text-white/70 sm:block">{T.addDesc}</p>
        <div className="mt-4 flex flex-col gap-2 sm:flex-row">
          <input
            required
            placeholder={T.domainPlaceholder}
            className="flex-1 rounded-lg border border-white/20 bg-white/10 px-3 py-3 text-base text-white placeholder-white/45 outline-none transition focus:border-accent sm:text-sm"
            value={newHostname}
            onChange={(e) => setNewHostname(e.target.value)}
          />
          <button type="submit" disabled={busy} className="shrink-0 rounded-lg bg-gradient-to-b from-amber-400 to-accent px-5 py-3 text-sm font-bold text-ink shadow-sm transition hover:brightness-105 disabled:cursor-not-allowed disabled:opacity-60">
            {busy ? T.adding : purchaseMode && !activePurchase ? T.addAndContinue : T.add}
          </button>
        </div>
        {/* (Hata/sonuç) butonun HEMEN altında, kart tonuyla uyumlu — sayfa sonunda değil. */}
        {bulkMsg && (
          <p className="mt-3 rounded-lg border border-red-300/40 bg-red-500/15 px-3 py-2 text-xs font-medium text-red-100">{bulkMsg}</p>
        )}
        {notice && (
          <p className="mt-3 rounded-lg border border-emerald-300/40 bg-emerald-400/15 px-3 py-2 text-xs font-medium text-emerald-100">✓ {notice}</p>
        )}
        {(() => {
          const raw = newHostname.trim();
          const host = toBareHost(newHostname);
          if (host && raw.toLowerCase() !== host) {
            return (
              <p className="mt-2 text-xs text-white/60">
                {T.willBeAdded} <span className="font-mono font-semibold text-white">{host}</span>{' '}
                (<code>https://</code>, <code>www.</code> {T.stripNote1})
              </p>
            );
          }
          return null;
        })()}
      </div>
    </form>
  );

  const scheduledCard = (
    <a href="/schedules" className="flex items-center justify-between gap-4 rounded-2xl border border-brand-200 bg-gradient-to-br from-brand-50 to-white p-4 shadow-card transition hover:border-brand-300 sm:p-5">
            <span className="flex items-center gap-3.5">
              <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-brand text-white">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></svg>
              </span>
              <span className="min-w-0">
                <span className="block font-bold text-brand">{T.schedTitle}</span>
                <span className="mt-0.5 hidden text-sm text-ink-soft sm:block">{T.schedDesc}</span>
              </span>
            </span>
            <span className="shrink-0 whitespace-nowrap text-sm font-bold text-accent-600">{T.schedManage} →</span>
          </a>
  );

  const domainSection = (
    <>
      {validDomains.length > 0 && (
        <section id="verified-domains" className="mt-8 scroll-mt-24">
          <h2 className="text-sm font-bold uppercase tracking-wide text-ink-muted">{T.verifiedDomains}</h2>
          <div className="mt-3 space-y-2.5">
            {validDomains.map((d) => (
              <div key={d.id} className="card p-4">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">{starBtn(d.id)}<span className="truncate font-semibold text-ink">{d.hostname}</span></div>
                    <span className="mt-0.5 inline-flex items-center gap-1 text-xs font-medium text-emerald-600">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" /> {T.verifiedValid}
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-2 sm:shrink-0">
                    <button onClick={() => goToOrder(d.id)} className="btn-primary">
                      {purchaseMode ? T.continueWithDomain : T.startScan}
                    </button>
                    {!purchaseMode && (
                      <button onClick={() => del(d.id)} title={T.delete} aria-label={T.delete} className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-line bg-white text-ink-muted transition hover:border-red-300 hover:bg-red-50 hover:text-red-600">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14" /></svg>
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
        <section id="pending-domains" className="mt-8 scroll-mt-24">
          <h2 className="text-sm font-bold uppercase tracking-wide text-ink-muted">{T.pendingVerification}</h2>
          <div className="mt-3 space-y-2.5">
            {pendingDomains.map((d) => {
              const expired = d.status === 'verified' && !d.valid;
              const open = openId === d.id;
              return (
                <div key={d.id} id={`domain-${d.id}`} className="card p-4">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">{starBtn(d.id)}<span className="truncate font-semibold text-ink">{d.hostname}</span></div>
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
                      <button onClick={() => del(d.id)} title={T.delete} aria-label={T.delete} className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-line bg-white text-ink-muted transition hover:border-red-300 hover:bg-red-50 hover:text-red-600">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14" /></svg>
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
      <div className="flex flex-col gap-3 sm:grid sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center sm:gap-4">
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
            {/* (MOBIL) truncate mobilde tarihi kesiyordu; dar ekranda SARSIN, genis ekranda kirpilsin. */}
            <span className="mt-0.5 block text-xs text-ink-muted sm:truncate">
              {o.packageName} · {new Date(o.createdAt).toLocaleDateString(dateLocale)}
            </span>
          </span>
        </button>
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1.5 sm:justify-end">
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
            <button onClick={() => archiveOrder(o.id, false)} title={T.unarchive} aria-label={T.unarchive} className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-line text-ink-muted transition hover:border-brand-300 hover:text-brand">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M3 3h18v4H3z" /><path d="M5 7v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7M10 12h4" /></svg>
            </button>
          ) : (
            <>
              <button onClick={() => archiveOrder(o.id, true)} title={T.archive} aria-label={T.archive} className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-line text-ink-muted transition hover:border-brand-300 hover:text-brand">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M3 3h18v4H3z" /><path d="M5 7v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7M10 12h4" /></svg>
              </button>
              <button onClick={() => deleteOrder(o.id)} title={T.delete} aria-label={T.delete} className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-line text-ink-muted transition hover:border-red-300 hover:bg-red-50 hover:text-red-600">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14" /></svg>
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
    <main className="min-h-screen bg-canvas pb-16">
      {/* HERO — koyu yeşil gradyan (markanın 3. rengi); krem zemin + amber vurgu ile denge. */}
      <div className="bg-gradient-to-b from-brand to-brand-deep text-white">
        <div className="container-page max-w-5xl pt-12 pb-24">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-accent">{T.myPanel}</p>
            <span className="inline-flex items-center gap-2 text-xs text-white/70">
              <span className="relative flex h-2 w-2"><span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" /><span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" /></span>
              {T.online}
            </span>
          </div>
          <h1 className="mt-2 text-3xl font-extrabold tracking-tight sm:text-4xl">{purchaseMode ? T.selectDomain : T.startScanning}</h1>
          <p className="mt-2 max-w-xl text-sm leading-relaxed text-white/70">{T.heroSub}</p>
          {!purchaseMode && (
            <div className="mt-5 flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:gap-2.5">
              {([
                [validDomains.length, T.statDomains, 'domains', 'verified-domains', 'emerald'],
                [orders.length, T.statScans, 'history', 'scans-history', 'sky'],
                [pendingDomains.length, T.statPending, 'domains', 'pending-domains', 'amber'],
              ] as const).map(([n, lbl, tgt, id, tone]) => (
                <button key={lbl} type="button" onClick={() => goToSection(tgt, id)}
                  className={`inline-flex w-full items-baseline justify-start gap-1.5 rounded-pill border px-3 py-1.5 text-xs font-medium transition sm:w-auto ${CHIP_TONE[tone]}`}>
                  <strong className={`text-sm font-extrabold ${CHIP_NUM[tone]}`}>{n}</strong>{lbl}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* İÇERİK — hero'nun üstüne biner (kart yükseltme hissi). */}
      <div className="container-page max-w-5xl -mt-16">

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
          <div className="mt-8">{addDomainBlock}</div>
        </>
      ) : (
        <>
          {/* SEKMELER — Taramalarım · Alan Adları · Ekle (tek sütun, ortalı) */}
          <nav className="mx-auto flex w-fit max-w-full flex-wrap justify-center gap-2 rounded-2xl border border-line bg-white p-1.5 shadow-card">
            {([
              ['history', T.tabMyScans, orders.length],
              ['domains', T.tabDomains, validDomains.length],
              ['add', T.tabAdd, 0],
            ] as const).map(([key, label, count]) => (
              <button
                key={key}
                onClick={() => setTab(key)}
                aria-pressed={tab === key}
                className={`flex items-center gap-1.5 rounded-xl px-5 py-2.5 text-sm transition ${
                  tab === key
                    ? (key === 'add' ? 'bg-brand font-bold text-white shadow-sm' : 'bg-accent font-bold text-ink shadow-sm')
                    : 'font-medium text-ink-muted hover:bg-brand-50/70'
                }`}
              >
                {key === 'add' && <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" aria-hidden><path d="M12 5v14M5 12h14" /></svg>}
                {label}
                {count > 0 && <span className={`rounded-pill px-1.5 py-0.5 text-[10px] font-bold ${tab === key ? 'bg-ink/15 text-ink' : 'bg-line text-ink-soft'}`}>{count}</span>}
              </button>
            ))}
          </nav>

          {tab === 'domains' && (
            <div className="mt-6">
              <a href="/schedules" className="inline-flex items-center gap-2 rounded-pill border border-line bg-white px-3 py-1.5 text-sm font-semibold text-brand transition hover:border-brand-300">
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-brand text-white"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></svg></span>
                {T.schedTitle} →
              </a>
              {domainSection}
            </div>
          )}

          {tab === 'history' && (
            orders.length > 0 ? (
              <section id="scans-history" className="mt-6 scroll-mt-24">
                <div className="flex items-center justify-between">
                  <h2 className="text-sm font-bold uppercase tracking-wide text-ink-muted">{T.myScans}</h2>
                  <button onClick={toggleArchived} className="inline-flex shrink-0 items-center gap-1.5 rounded-pill border border-line bg-white px-3 py-1.5 text-xs font-semibold text-ink-soft transition hover:border-brand-300 hover:text-brand">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M3 3h18v4H3z" /><path d="M5 7v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7M10 12h4" /></svg>
                    {showArchived ? T.hideArchived : T.archived}
                    {archivedOrders && archivedOrders.length > 0 ? ` (${archivedOrders.length})` : ''}
                  </button>
                </div>
                {/* (Arama) Taramalarım içinde alan adı / paket ara. */}
                <div className="relative mt-3">
                  <svg className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-ink-muted" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><circle cx="11" cy="11" r="8" /><path d="m21 21-4.3-4.3" /></svg>
                  <input value={scanQuery} onChange={(e) => setScanQuery(e.target.value)} placeholder={T.scanSearch} aria-label={T.scanSearch}
                    className="w-full rounded-lg border border-line bg-white py-2.5 pl-9 pr-3 text-base text-ink outline-none transition focus:border-brand-300 sm:text-sm" />
                </div>
                <div className="card mt-3 divide-y divide-line overflow-hidden">
                  {shownHistory.length > 0 ? shownHistory.map((o) => orderCard(o, false)) : (
                    <p className="px-5 py-6 text-center text-sm text-ink-muted">{T.noScanMatch}</p>
                  )}
                  {!scanQuery.trim() && orders.length > HISTORY_PREVIEW && (
                    <button
                      onClick={() => setShowAllHistory((v) => !v)}
                      className="flex w-full items-center justify-center gap-1.5 bg-brand-50/40 px-5 py-3 text-sm font-bold text-brand transition hover:bg-brand-50"
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

          {/* EKLE sekmesi — aşağı doğru açılan, ortalı, ince yeşil panel */}
          {tab === 'add' && (
            <div className="mx-auto mt-6 max-w-xl">{addDomainBlock}</div>
          )}
        </>
      )}
      </div>
    </main>
  );
}
