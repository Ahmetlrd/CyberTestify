/**
 * SEVIYE 1 — Filtreleyen Egress Proxy.
 *
 * PentAGI tarama container'lari (pentagi-terminal-*) tum HTTP/HTTPS trafigini
 * bu proxy uzerinden gecirir (PentAGI .env: PROXY_URL). Proxy, her istegin hedef
 * host/IP'sini o an AKTIF olan TEK flow'un kapsamiyla karsilastirir:
 *   - Kapsam ici (dogrulanan hostname + resolvedIps + referans allowlist +
 *     private/loopback) → gecer.
 *   - Kapsam disi → REDDEDER (403 / tunnel kapatilir) + backend'e audit yazar.
 *
 * Kapsam mantigi services/scope.ts'ten IMPORT edilir (Seviye 3 ile ayni kod).
 * Concurrency=1 oldugu icin "aktif kapsam" tek flow'a aittir (bkz orchestrator).
 *
 * Proaktif katman: onceki katmanlar tespit edip durduruyordu (reaktif); bu
 * katman istegin cikmasini BASTAN engelliyor.
 */
import http from 'node:http';
import net from 'node:net';
import { URL } from 'node:url';
import { config, validateScopeLockConfig } from '../config.js';
import { isInScope, type Scope } from '../services/scope.js';

// Fail-fast: yanlis/eksik konfigurasyonla ayaga kalkma.
validateScopeLockConfig();

interface ActiveScope {
  active: boolean;
  flowId?: string;
  hostname?: string;
  ips?: string[];
  allowlist: string[];
  passiveOnly?: boolean;
  securityProfile?: 'passive' | 'active-light';
}

// Pasif paketlerde izin verilen (veri DEGISTIRMEYEN) HTTP metotlari.
const PASSIVE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
// active-light profilinde EK olarak POST serbest (zafiyeti DOGRULAMAK icin kontrollu
// test payload'i); DELETE/PATCH/PUT (veri silme/degistirme) HALA yasak. Asil metot
// zorlamasi HTTPS'te Go tool-guard'da (passive_guard.go) — bu proxy DUZ HTTP icin.
const ACTIVE_LIGHT_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'POST']);

// active-light DoS/flood freni: flow basina 60 sn penceresinde azami istek. Pasif
// profil zaten GET-only + dar promptlu; sayac yine de tutulur, enforce yalniz active-light.
const RATE_WINDOW_MS = 60_000;
const ACTIVE_LIGHT_MAX_REQ_PER_WINDOW = 240;
const rate = new Map<string, { windowStart: number; count: number }>();

// flow basina kayan pencere sayaci; profile 'active-light' ise limit asiminda false.
function rateLimitOk(flowId: string | undefined, profile: 'passive' | 'active-light'): boolean {
  const key = flowId ?? '__no_flow__';
  const now = Date.now();
  const r = rate.get(key);
  if (!r || now - r.windowStart >= RATE_WINDOW_MS) {
    rate.set(key, { windowStart: now, count: 1 });
    return true;
  }
  r.count += 1;
  if (profile === 'active-light' && r.count > ACTIVE_LIGHT_MAX_REQ_PER_WINDOW) return false;
  return true;
}

function allowedMethodsFor(a: ActiveScope): Set<string> {
  // Metot politikasi GUVENLIK PROFILINDEN turetilir (passiveOnly=networkLayer, ayri eksen).
  return (a.securityProfile ?? 'passive') === 'active-light' ? ACTIVE_LIGHT_METHODS : PASSIVE_METHODS;
}

// Aktif kapsami backend'ten cek, kisa TTL ile cache'le (istek basina DB'ye gitme).
let cache: { at: number; scope: ActiveScope } | null = null;
const CACHE_MS = 2000;

async function getActiveScope(): Promise<ActiveScope> {
  if (cache && Date.now() - cache.at < CACHE_MS) return cache.scope;
  try {
    const res = await fetch(`${config.backendInternalUrl}/internal/active-scope`, {
      headers: { 'x-internal-secret': config.internalApiSecret },
    });
    const scope = (await res.json()) as ActiveScope;
    cache = { at: Date.now(), scope };
    return scope;
  } catch (err) {
    console.error('[egress-proxy] Aktif kapsam alinamadi, guvenli tarafta reddediliyor:', err);
    // Backend'e ulasilamiyorsa fail-closed: yalnizca allowlist/private gecsin.
    return { active: false, allowlist: config.scopeAllowlist };
  }
}

function toScope(a: ActiveScope): Scope {
  return {
    hostname: a.active && a.hostname ? a.hostname : '__no_active_scan__',
    ips: a.active && a.ips ? a.ips : [],
    allowlist: a.allowlist ?? config.scopeAllowlist,
  };
}

function auditBlock(target: string) {
  // Fire-and-forget: backend audit'ine yaz.
  fetch(`${config.backendInternalUrl}/internal/scope-audit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-internal-secret': config.internalApiSecret },
    body: JSON.stringify({ target }),
  }).catch(() => {});
}

async function allowed(host: string): Promise<boolean> {
  const active = await getActiveScope();
  return isInScope(host, toScope(active));
}

const server = http.createServer();

// --- Duz HTTP (forward proxy): req.url mutlak URL olur -------------------
server.on('request', async (req, res) => {
  // Saglik kontrolu: backend/worker bu endpoint ile proxy'nin ayakta oldugunu
  // dogrular (dogrudan istek, proxy istegi degil).
  if (req.url === '/health') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, service: 'egress-proxy' }));
    return;
  }

  // Forward proxy'de req.url MUTLAK URL olur (http://host/...). Degilse (or.
  // dogrudan istek) proxy istegi degildir → 400.
  let target: URL;
  try {
    target = new URL(req.url ?? '');
    if (target.protocol !== 'http:' && target.protocol !== 'https:') throw new Error('scheme');
  } catch {
    res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('Bu bir HTTP forward proxy. Mutlak URL bekleniyor.');
    return;
  }
  const host = target.hostname;

  // METOT FILTRESI (defense-in-depth): GUVENLIK PROFILINE gore izinli metotlar.
  // passive → GET/HEAD/OPTIONS; active-light → +POST (DELETE/PATCH/PUT hala yasak).
  // NOT: HTTPS CONNECT tunelinde metot sifrelidir, gorunmez → orada asil enforce Go
  // tool-guard (passive_guard.go) + worker'daki tool-call tespitidir.
  const activeScope = await getActiveScope();
  const profile = activeScope.securityProfile ?? 'passive';
  const method = (req.method ?? 'GET').toUpperCase();
  if (!allowedMethodsFor(activeScope).has(method)) {
    auditBlock(`forbidden-method:${method} ${host}`);
    console.warn(`[egress-proxy][BLOCK] Yasak HTTP metodu (${profile}): ${method} ${host}`);
    res.writeHead(405, { 'content-type': 'text/plain; charset=utf-8', allow: [...allowedMethodsFor(activeScope)].join(', ') });
    res.end('Bu tarama profili bu HTTP metoduna izin vermiyor (egress policy).');
    return;
  }
  // active-light DoS/flood freni (flow basina kayan pencere).
  if (!rateLimitOk(activeScope.flowId, profile)) {
    auditBlock(`rate-limit:${method} ${host}`);
    console.warn(`[egress-proxy][BLOCK] Hiz limiti (active-light): flow ${activeScope.flowId} ${host}`);
    res.writeHead(429, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('Hiz limiti asildi (egress policy).');
    return;
  }

  if (!(await allowed(host))) {
    auditBlock(host);
    console.warn(`[egress-proxy][BLOCK] HTTP kapsam disi: ${host}`);
    res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('Kapsam disi hedef engellendi (egress policy).');
    return;
  }

  const proxyReq = http.request(
    {
      hostname: target.hostname,
      port: target.port || 80,
      path: target.pathname + target.search,
      method: req.method,
      headers: req.headers,
    },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
      proxyRes.pipe(res);
    },
  );
  proxyReq.on('error', () => res.writeHead(502).end('bad gateway'));
  req.pipe(proxyReq);
});

// --- HTTPS (CONNECT tunnel): req.url = "host:port" -----------------------
server.on('connect', async (req, clientSocket, head) => {
  const [host, portStr] = (req.url ?? '').split(':');
  const port = Number(portStr) || 443;

  // active-light DoS/flood freni: her CONNECT tuneli bir istek sayilir.
  const active = await getActiveScope();
  if (!rateLimitOk(active.flowId, active.securityProfile ?? 'passive')) {
    auditBlock(`rate-limit:CONNECT ${host}`);
    console.warn(`[egress-proxy][BLOCK] Hiz limiti (active-light) CONNECT: flow ${active.flowId} ${host}`);
    clientSocket.write('HTTP/1.1 429 Too Many Requests\r\n\r\nHiz limiti asildi.\r\n');
    clientSocket.destroy();
    return;
  }

  if (!host || !(await allowed(host))) {
    auditBlock(host || (req.url ?? ''));
    console.warn(`[egress-proxy][BLOCK] CONNECT kapsam disi: ${req.url}`);
    clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\nKapsam disi hedef engellendi.\r\n');
    clientSocket.destroy();
    return;
  }

  const serverSocket = net.connect(port, host, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    serverSocket.write(head);
    serverSocket.pipe(clientSocket);
    clientSocket.pipe(serverSocket);
  });
  serverSocket.on('error', () => clientSocket.destroy());
  clientSocket.on('error', () => serverSocket.destroy());
});

// Tek bir hatali istek/soket proxy'yi ASLA dusurmesin (surekli calismali).
process.on('uncaughtException', (err) => console.error('[egress-proxy] uncaughtException:', err));
process.on('unhandledRejection', (err) => console.error('[egress-proxy] unhandledRejection:', err));
server.on('clientError', (_err, socket) => socket.destroy());

server.listen(config.egressProxyPort, () => {
  console.log(`[egress-proxy] Filtreleyen egress proxy ${config.egressProxyPort} portunda dinliyor.`);
  console.log(`[egress-proxy] Aktif kapsam kaynagi: ${config.backendInternalUrl}/internal/active-scope`);
});
