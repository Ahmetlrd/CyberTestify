/**
 * Buffer GraphQL API istemcisi — LinkedIn sirket sayfasina otomatik paylasim.
 *
 * ONEMLI: Buffer'in ESKI v1 REST API'si (api.bufferapp.com/1/updates/create.json) 2019'da
 * KAPATILDI. Burada YALNIZ guncel GraphQL API'si kullanilir: tek endpoint (https://api.buffer.com),
 * POST + { query, variables }, `Authorization: Bearer <API_KEY>`.
 *
 * Semanin tamami canli API'ye introspection ile dogrulandi (tahmin YOK):
 *   - Query.channels(input:{organizationId}) -> { id name service type }
 *   - Mutation.createPost(input: CreatePostInput!) -> union PostActionPayload
 *       CreatePostInput ZORUNLU alanlar: channelId, mode, needsApproval, schedulingType, assets
 *       (assets NON_NULL'dur; gorsel yoksa BOS LISTE gonderilir)
 *   - ShareMode enum: addToQueue | customScheduled | shareNext | shareNow
 *   - SchedulingType enum: automatic | notification
 *   - PostStatus enum: draft | error | needs_approval | scheduled | sending | sent
 *   - Gorsel: assets: [{ image: { url } }] — url PUBLIC erisilebilir olmali
 *   - Mutation.deletePost(input:{id}) -> union DeletePostPayload
 *   - Hata tipleri `MutationError` INTERFACE'ini uygular -> `... on MutationError { message }`
 *
 * API anahtari YALNIZ backend env'de (BUFFER_API_KEY); asla loglanmaz, asla istemciye donmez.
 */
import { config } from '../config.js';

const BUFFER_ENDPOINT = 'https://api.buffer.com';
const TIMEOUT_MS = 20_000;

export class BufferError extends Error {}

/** Anahtar yoksa ozellik kapali — cagri yapilmaz, admin panelinde net mesaj gosterilir. */
export function bufferEnabled(): boolean {
  return !!config.buffer.apiKey;
}

async function gql<T>(query: string, variables?: Record<string, unknown>): Promise<T> {
  if (!config.buffer.apiKey) throw new BufferError('BUFFER_API_KEY tanımlı değil — Buffer entegrasyonu kapalı.');
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetch(BUFFER_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${config.buffer.apiKey}` },
      body: JSON.stringify({ query, variables }),
      signal: ctrl.signal,
    });
  } catch (e: any) {
    // NOT: hata mesajina ASLA anahtar/deger eklenmez.
    throw new BufferError(e?.name === 'AbortError' ? 'Buffer API zaman aşımına uğradı.' : 'Buffer API’ye ulaşılamadı.');
  } finally {
    clearTimeout(timer);
  }
  const body = (await res.json().catch(() => null)) as any;
  if (!res.ok || !body) throw new BufferError(`Buffer API hatası (HTTP ${res.status}).`);
  if (Array.isArray(body.errors) && body.errors.length) {
    throw new BufferError(String(body.errors[0]?.message ?? 'Buffer API hatası.'));
  }
  return body.data as T;
}

// --- Organizasyon + kanal ID'leri: bir kere cozulup CACHE'lenir (sik degismez) ----------------
let cached: { organizationId: string; channelId: string; channelName: string } | null = null;

export async function resolveLinkedInTarget(force = false): Promise<{ organizationId: string; channelId: string; channelName: string }> {
  if (cached && !force) return cached;

  // env'de sabitlenmisse hic sorgulama (deploy'da tek kaynak).
  let organizationId = config.buffer.organizationId;
  if (!organizationId) {
    const d = await gql<{ account: { organizations: Array<{ id: string; name: string }> } }>(
      'query { account { organizations { id name } } }',
    );
    organizationId = d.account?.organizations?.[0]?.id ?? '';
    if (!organizationId) throw new BufferError('Buffer hesabında organizasyon bulunamadı.');
  }

  let channelId = config.buffer.linkedinChannelId;
  let channelName = 'LinkedIn';
  if (!channelId) {
    const d = await gql<{ channels: Array<{ id: string; name: string; service: string; type: string }> }>(
      'query($input: ChannelsInput!) { channels(input: $input) { id name service type } }',
      { input: { organizationId } },
    );
    const li = (d.channels ?? []).find((c) => c.service === 'linkedin');
    if (!li) {
      throw new BufferError(
        'Buffer hesabında bağlı bir LinkedIn kanalı yok. Buffer → Channels → Add Channel → LinkedIn Page adımını tamamlayın.',
      );
    }
    channelId = li.id;
    channelName = li.name;
  }

  cached = { organizationId, channelId, channelName };
  return cached;
}

// --- Post olusturma ---------------------------------------------------------------------------
export type BufferShareMode = 'addToQueue' | 'customScheduled';

export type BufferCreatedPost = { id: string; status: string | null; dueAt: string | null };

const CREATE_POST = `
mutation CreateBufferPost($input: CreatePostInput!) {
  createPost(input: $input) {
    __typename
    ... on PostActionSuccess { post { id status dueAt text } }
    ... on MutationError { message }
  }
}`;

/**
 * LinkedIn gonderisi olusturur.
 *  - mode 'addToQueue'      -> Buffer siradaki uygun zaman slotuna koyar (dueAt gerekmez)
 *  - mode 'customScheduled' -> dueAt (ISO 8601, UTC) zorunlu; tam tarih/saat
 * imageUrl verilirse assets: [{ image: { url } }] gonderilir (URL PUBLIC olmali).
 */
export async function scheduleLinkedInPost(opts: {
  text: string;
  mode: BufferShareMode;
  dueAt?: string | null;
  imageUrl?: string | null;
  /** (NATIF CAROUSEL) PUBLIC PDF URL'i — LinkedIn bunu kaydirilabilir dokuman olarak gosterir. */
  documentUrl?: string | null;
  /** Dokuman basligi: LinkedIn carousel'in ustunde gorunur, TIKLAMAYI belirgin etkiler. */
  documentTitle?: string | null;
  channelId?: string;
}): Promise<BufferCreatedPost> {
  const target = opts.channelId ? { channelId: opts.channelId } : await resolveLinkedInTarget();
  if (opts.mode === 'customScheduled' && !opts.dueAt) {
    throw new BufferError('Belirli tarihte paylaşım için tarih/saat zorunludur.');
  }
  const input: Record<string, unknown> = {
    text: opts.text,
    channelId: target.channelId,
    schedulingType: 'automatic',
    mode: opts.mode,
    needsApproval: false, // sema'da NON_NULL — acikca gonderilmeli
    // assets NON_NULL. Sema (introspection ile dogrulandi): AssetInput { document | image | video },
    // DocumentAssetInput { url, title, thumbnailUrl }. Dokuman ve gorsel AYNI ANDA gonderilmez —
    // LinkedIn dokuman gonderisinde ayrica gorsel tasimaz; dokuman onceliklidir.
    assets: opts.documentUrl
      ? [{ document: { url: opts.documentUrl, title: opts.documentTitle || 'CyberTestify' } }]
      : opts.imageUrl
        ? [{ image: { url: opts.imageUrl } }]
        : [],
  };
  if (opts.mode === 'customScheduled') input.dueAt = new Date(opts.dueAt as string).toISOString();

  const d = await gql<{ createPost: any }>(CREATE_POST, { input });
  const r = d.createPost;
  if (r?.__typename === 'PostActionSuccess' && r.post?.id) {
    return { id: r.post.id, status: r.post.status ?? null, dueAt: r.post.dueAt ?? null };
  }
  // Hata union'i: NotFoundError / InvalidInputError / LimitReachedError / ... hepsi MutationError uygular.
  throw new BufferError(String(r?.message ?? 'Buffer gönderiyi oluşturamadı.'));
}

/** Buffer'daki gonderiyi SILER — iptal ederken DB'den silmek TEK BASINA yetersizdir. */
export async function deleteBufferPost(postId: string): Promise<void> {
  const d = await gql<{ deletePost: any }>(
    `mutation DeleteBufferPost($input: DeletePostInput!) {
       deletePost(input: $input) { __typename ... on MutationError { message } }
     }`,
    { input: { id: postId } },
  );
  const r = d.deletePost;
  if (r?.__typename && r.__typename !== 'DeletePostSuccess') {
    throw new BufferError(String(r?.message ?? 'Buffer gönderisi silinemedi.'));
  }
}

/** Tek gonderinin guncel durumu (durum senkronu icin). Bulunamazsa null. */
export async function getBufferPost(postId: string): Promise<{ status: string | null; dueAt: string | null; sentAt: string | null } | null> {
  try {
    const d = await gql<{ post: any }>(
      'query GetBufferPost($input: PostInput!) { post(input: $input) { id status dueAt sentAt } }',
      { input: { id: postId } },
    );
    if (!d.post) return null;
    return { status: d.post.status ?? null, dueAt: d.post.dueAt ?? null, sentAt: d.post.sentAt ?? null };
  } catch {
    return null; // durum senkronu BEST-EFFORT; basarisizsa DB'deki son durum korunur
  }
}
