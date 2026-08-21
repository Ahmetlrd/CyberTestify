/**
 * (OTONOM AI RED TEAM — ŞEFFAFLIK) Ham flow → OKUNAKLI AJAN TRANSKRİPTİ.
 * Girdi = binder --dump-raw çıktısı ({meta, claims, artifacts}); saf/deterministik, LLM YOK.
 * Amaç: müşteri "gerçekten saldırdı, işte ne yaptı" diye görebilsin + biz 0-kanıtlı'yı KÖR debug etmeyelim.
 *  - artifacts: ajanın çalıştırdığı araç/komut (command) + aldığı çıktı/yanıt (rawText).
 *  - claims: ajanın SÖYLEDİĞİ sonuç/bulgu (kanıt DEĞİL — üç-katman binder'da bağlanır).
 * Secret'lar binder --dump-raw'da redact() ile maskeli gelir; burada ek maskeSecrets defans olarak uygulanır.
 * Rapor motoruna / üç-katmana DOKUNMAZ — yalnız görünürlük.
 */
import { maskSecrets } from './puller.js';

export type RawArtifact = { id: string; kind?: string; command?: string; rawText?: string };
export type RawClaim = { id: string; title?: string; text?: string };
export type RawFlow = { meta?: Record<string, unknown>; claims?: RawClaim[]; artifacts?: RawArtifact[] };

export type TranscriptEntry = {
  seq: number;
  kind: 'arac' | 'sonuc';          // araç-çağrısı (istek/yanıt) | ajan sonucu/iddiası
  role: string;                    // pentester/terminal/searcher... (araç adı) ya da 'ajan'
  request?: string;                // gönderilen komut/istek satırı
  requestHost?: string;            // isteğin atıldığı host (provenance şeffaflığı)
  status?: string;                 // HTTP status satırı (varsa)
  responseExcerpt?: string;        // yanıttan ANLAMLI kesit (marker/payload yansıması öne alınır)
  markerReflected?: boolean;       // enjekte işaret yanıtta ENCODE-EDİLMEDEN yansıdı mı (kanıt sinyali)
  text?: string;                   // ajan sonucu (kind='sonuc')
};

const num = (id: string): number => {
  const m = /#(\d+)/.exec(id || '');
  return m ? Number(m[1]) : 0;
};

/** curl komutundan isteğin GERÇEKTEN atıldığı host (URL / Host header / --resolve). Provenance ile aynı temel. */
export function requestHostOf(command: string): string {
  const c = command || '';
  const url = /https?:\/\/([a-z0-9.\-]+)/i.exec(c);
  if (url) return url[1].toLowerCase();
  const host = /-H\s*["']?\s*host:\s*([a-z0-9.\-]+)/i.exec(c);
  if (host) return host[1].toLowerCase();
  const res = /--resolve\s+([a-z0-9.\-]+):/i.exec(c);
  if (res) return res[1].toLowerCase();
  return '';
}

const HTTP_STATUS = /HTTP\/\d(?:\.\d)?\s+\d{3}[^\n]*/i;

/** Enjekte işaret/payload (zqx…marker, <script>, "><tag) yanıtta ENCODE-EDİLMEDEN geçiyor mu? */
function reflectionLine(command: string, body: string): { reflected: boolean; line?: string } {
  const marker = /zqx[a-z0-9]*marker[a-z0-9]*/i.exec(command || '') || /zqx[a-z0-9]*marker[a-z0-9]*/i.exec(body || '');
  const needles: string[] = [];
  if (marker) needles.push(marker[0]);
  for (const p of ['<script', '<img', '"><', 'onerror=', 'alert(']) if ((command || '').toLowerCase().includes(p)) needles.push(p);
  for (const n of needles) {
    const idx = (body || '').toLowerCase().indexOf(n.toLowerCase());
    if (idx >= 0 && !/&lt;|&gt;|&#/.test((body || '').slice(Math.max(0, idx - 4), idx + n.length + 4))) {
      // needle gövdede var + çevresi HTML-encode DEĞİL → yansıma
      const start = body.lastIndexOf('\n', idx) + 1;
      let end = body.indexOf('\n', idx);
      if (end < 0) end = Math.min(body.length, idx + 160);
      return { reflected: true, line: body.slice(start, end).trim().slice(0, 220) };
    }
  }
  return { reflected: false };
}

/** Yanıt gövdesinden anlamlı kesit: status satırı + (varsa) yansıma satırı, yoksa ilk anlamlı gövde. */
function responseExcerpt(command: string, raw: string): { status?: string; excerpt?: string; markerReflected: boolean } {
  const body = raw || '';
  const st = HTTP_STATUS.exec(body);
  const refl = reflectionLine(command, body);
  if (refl.reflected && refl.line) return { status: st?.[0]?.slice(0, 120), excerpt: refl.line, markerReflected: true };
  // yansıma yoksa: gövdenin ilk anlamlı ~240 karakteri (boş satırlar sıkıştırılmış)
  const compact = body.replace(/\n{2,}/g, '\n').trim();
  const afterStatus = st ? compact.slice(compact.indexOf(st[0]) + st[0].length).trim() : compact;
  return { status: st?.[0]?.slice(0, 120), excerpt: (afterStatus || compact).slice(0, 240), markerReflected: false };
}

/**
 * Ham flow → sıralı okunaklı transkript. Araç-çağrıları (istek/yanıt) zaman-sırasına yakın (id) dizilir;
 * ajan sonuçları/iddiaları ayrı 'sonuc' satırları olarak eklenir. Her satır maskeSecrets'ten geçer.
 */
export function renderTranscript(raw: RawFlow | null | undefined): TranscriptEntry[] {
  if (!raw) return [];
  const entries: TranscriptEntry[] = [];
  const artifacts = [...(raw.artifacts ?? [])].sort((a, b) => num(a.id) - num(b.id));
  for (const art of artifacts) {
    const command = maskSecrets(art.command ?? '');
    const rawText = maskSecrets(art.rawText ?? '');
    const { status, excerpt, markerReflected } = responseExcerpt(command, rawText);
    entries.push({
      seq: 0,
      kind: 'arac',
      role: (art.kind || 'arac').toString(),
      request: command.slice(0, 400) || undefined,
      requestHost: command ? requestHostOf(command) || undefined : undefined,
      status,
      responseExcerpt: excerpt,
      markerReflected,
    });
  }
  for (const c of raw.claims ?? []) {
    const text = maskSecrets(c.text ?? c.title ?? '');
    if (text.trim()) entries.push({ seq: 0, kind: 'sonuc', role: 'ajan', text: text.slice(0, 500) });
  }
  return entries.map((e, i) => ({ ...e, seq: i + 1 }));
}
