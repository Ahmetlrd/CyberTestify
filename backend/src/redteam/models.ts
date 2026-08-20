/**
 * (OTONOM RED TEAM — MODEL YÖNETİMİ) PentAGI ajan-rolleri için model seçimi + fiyat tablosu + maliyet
 * tahmini. Fiyatlar PLACEHOLDER/CONFIG (Vedat ayarlar; env ile override). Varsayılan MALİYET-GÜVENLİ
 * (Opus YOK). Opus seçilebilir ama "pahalı" uyarısı + tahmini etki gösterilir.
 *
 * NOT: PentAGI'nin anthropic profil model-config'i imaja gömülüdür; runner setup-pentagi'de bir
 * provider-override config'i (config.yml mount) yazarak bu seçimi uygular.
 */

export type ModelId = 'claude-haiku-4-5' | 'claude-sonnet-4-5' | 'claude-opus-4-5';

/** Model fiyatı: milyon token başına USD (in/out). Env: REDTEAM_PRICE_<MODEL>_IN/_OUT ile override. */
function priceFromEnv(model: string, def: { inM: number; outM: number }): { inM: number; outM: number } {
  const key = model.toUpperCase().replace(/[^A-Z0-9]/g, '_');
  const i = Number(process.env[`REDTEAM_PRICE_${key}_IN`]);
  const o = Number(process.env[`REDTEAM_PRICE_${key}_OUT`]);
  return { inM: Number.isFinite(i) && i > 0 ? i : def.inM, outM: Number.isFinite(o) && o > 0 ? o : def.outM };
}

export const MODEL_CATALOG: Array<{ id: ModelId; label: string; tier: 'ucuz' | 'dengeli' | 'pahalı'; price: { inM: number; outM: number }; expensive: boolean }> = [
  { id: 'claude-haiku-4-5', label: 'Haiku 4.5 (en ucuz)', tier: 'ucuz', price: priceFromEnv('claude-haiku-4-5', { inM: 1, outM: 5 }), expensive: false },
  { id: 'claude-sonnet-4-5', label: 'Sonnet 4.5 (dengeli)', tier: 'dengeli', price: priceFromEnv('claude-sonnet-4-5', { inM: 3, outM: 15 }), expensive: false },
  { id: 'claude-opus-4-5', label: 'Opus 4.5 (pahalı)', tier: 'pahalı', price: priceFromEnv('claude-opus-4-5', { inM: 15, outM: 75 }), expensive: true },
];
export function modelPrice(id: string): { inM: number; outM: number } {
  return (MODEL_CATALOG.find((m) => m.id === id) ?? MODEL_CATALOG[1]).price;
}

/** PentAGI ajan-rolleri (anthropic profil config.yml). */
export const PENTAGI_ROLES = [
  'simple', 'simple_json', 'primary_agent', 'assistant', 'generator', 'refiner',
  'adviser', 'reflector', 'searcher', 'enricher', 'coder', 'installer', 'pentester',
] as const;
export type PentagiRole = (typeof PENTAGI_ROLES)[number];

/** Hangi roller "ajan" (çok çağrı yapan, maliyet-dominant). */
const AGENT_ROLES: PentagiRole[] = ['primary_agent', 'pentester', 'coder', 'assistant'];

/** MALİYET-GÜVENLİ varsayılan: hafif roller Haiku, ajan rolleri Sonnet, Opus YOK. */
export const DEFAULT_ROLE_MODELS: Record<PentagiRole, ModelId> = {
  simple: 'claude-haiku-4-5', simple_json: 'claude-haiku-4-5', reflector: 'claude-haiku-4-5',
  searcher: 'claude-haiku-4-5', enricher: 'claude-haiku-4-5',
  primary_agent: 'claude-sonnet-4-5', assistant: 'claude-sonnet-4-5', refiner: 'claude-sonnet-4-5',
  adviser: 'claude-sonnet-4-5', coder: 'claude-sonnet-4-5', installer: 'claude-sonnet-4-5',
  pentester: 'claude-sonnet-4-5',
  generator: 'claude-sonnet-4-5', // profil Opus; maliyet-güvenli varsayılan Sonnet'e indirir
};

export type ModelConfig = Partial<Record<PentagiRole, ModelId>>;

/** Eksik rolleri varsayılanla tamamla + geçersiz model → varsayılan. */
export function normalizeModelConfig(cfg: ModelConfig | null | undefined): Record<PentagiRole, ModelId> {
  const out = { ...DEFAULT_ROLE_MODELS };
  if (cfg) {
    for (const role of PENTAGI_ROLES) {
      const m = cfg[role];
      if (m && MODEL_CATALOG.some((c) => c.id === m)) out[role] = m;
    }
  }
  return out;
}

// Kabaca çağrı başına token (tahmin için; gerçek maliyet puller'dan msgchains'ten gelir).
const PER_CALL = { inTok: 4000, outTok: 1000 };

/**
 * Koşu-öncesi maliyet TAHMİNİ: cap (max çağrı) + rol→model karışımına göre. Dominant = ajan rolleri.
 * Gerçek maliyet daha düşük olabilir (cap üst sınır). Opus varsa uyarı.
 */
export function estimateRunCost(
  capCalls: number,
  cfg: ModelConfig | null | undefined,
): { estUsd: number; dominantModel: ModelId; hasOpus: boolean; note: string; perModel: Array<{ model: ModelId; sharePct: number; estUsd: number }> } {
  const models = normalizeModelConfig(cfg);
  const dominant = models.primary_agent;
  const hasOpus = Object.values(models).some((m) => m === 'claude-opus-4-5');

  // Çağrı dağılımı yaklaşık: %55 ajan rolleri (dominant), %45 hafif roller ortalaması.
  const agentModel = dominant;
  const lightModels = PENTAGI_ROLES.filter((r) => !AGENT_ROLES.includes(r) && r !== 'generator').map((r) => models[r]);
  const lightAvg = lightModels.length ? lightModels : [models.simple];

  const callCost = (m: ModelId) => (PER_CALL.inTok / 1e6) * modelPrice(m).inM + (PER_CALL.outTok / 1e6) * modelPrice(m).outM;
  const agentCalls = Math.round(capCalls * 0.55);
  const lightCalls = capCalls - agentCalls;
  const lightPerCall = lightAvg.reduce((a, m) => a + callCost(m), 0) / lightAvg.length;

  const agentUsd = agentCalls * callCost(agentModel);
  const lightUsd = lightCalls * lightPerCall;
  const estUsd = Math.round((agentUsd + lightUsd) * 10000) / 10000;

  return {
    estUsd,
    dominantModel: dominant,
    hasOpus,
    note: hasOpus
      ? 'DİKKAT: Opus seçili — maliyet belirgin artar. İlk koşu için Sonnet/Haiku önerilir.'
      : 'Maliyet-güvenli config. Değer cap üst-sınırından hesaplanır; gerçek maliyet daha düşük olabilir.',
    perModel: [
      { model: agentModel, sharePct: 55, estUsd: Math.round(agentUsd * 10000) / 10000 },
      { model: lightAvg[0], sharePct: 45, estUsd: Math.round(lightUsd * 10000) / 10000 },
    ],
  };
}
