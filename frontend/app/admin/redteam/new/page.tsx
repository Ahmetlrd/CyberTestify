'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { adminApi } from '../../../../lib/adminApi';
import { H1, card } from '../../../../components/admin/ui';

const inp: React.CSSProperties = { padding: '6px 10px', borderRadius: 6, border: '1px solid #334155', background: '#0f172a', color: '#e2e8f0', fontSize: 13 };
const lbl: React.CSSProperties = { fontSize: 12, color: '#94a3b8', display: 'block', marginBottom: 4 };

export default function AdminRedTeamNew() {
  const router = useRouter();
  const [cat, setCat] = useState<any>(null);
  const [domain, setDomain] = useState('');
  const [level, setLevel] = useState('S1');
  const [models, setModels] = useState<Record<string, string>>({});
  const [advanced, setAdvanced] = useState(false);
  const [capCalls, setCapCalls] = useState<string>('');
  const [dryRun, setDryRun] = useState(true);
  const [est, setEst] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    adminApi.redteamModelCatalog().then((c) => { setCat(c); setModels(c.defaults); }).catch((e) => setError(e.message));
  }, []);

  // Canlı maliyet tahmini (seviye/model/cap değişince)
  useEffect(() => {
    if (!cat) return;
    const t = setTimeout(() => {
      adminApi.redteamEstimate({ level, modelConfig: models, capCallsOverride: capCalls ? Number(capCalls) : undefined }).then(setEst).catch(() => {});
    }, 300);
    return () => clearTimeout(t);
  }, [cat, level, models, capCalls]);

  const levelCap = useMemo(() => cat?.levels?.[level], [cat, level]);

  async function start() {
    setError(null);
    if (domain.trim().length < 3) { setError('Geçerli bir hedef girin.'); return; }
    setBusy(true);
    try {
      const r = await adminApi.redteamCreate({
        domain: domain.trim(), level, modelConfig: models,
        capCallsOverride: capCalls ? Number(capCalls) : undefined, dryRun,
      });
      router.push(`/admin/redteam/${r.jobId}`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (error && !cat) return <><H1>Yeni Red Team Koşusu</H1><p style={{ color: '#fca5a5' }}>{error}</p></>;
  if (!cat) return <><H1>Yeni Red Team Koşusu</H1><p style={{ color: '#94a3b8' }}>Yükleniyor…</p></>;

  return (
    <>
      <Link href="/admin/redteam" style={{ color: '#94a3b8', fontSize: 13 }}>← Red Team</Link>
      <H1>Yeni Red Team Koşusu</H1>
      <p style={{ fontSize: 12, color: '#fbbf24', margin: '-8px 0 14px' }}>
        ⚠ Yalnız SAHİBİ olduğun hedef. İlk koşu için S1 + dry-run önerilir (maliyet yakmadan zinciri doğrular).
      </p>

      <div style={{ ...card, display: 'grid', gap: 14, maxWidth: 640 }}>
        <div>
          <label style={lbl}>Hedef (kendi siten)</label>
          <input style={{ ...inp, width: '100%' }} value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="ornek: ipekbilgisayar.com" />
        </div>

        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <label style={lbl}>Seviye</label>
            <select style={inp} value={level} onChange={(e) => setLevel(e.target.value)}>
              {['S1', 'S2', 'S3'].map((l) => <option key={l} value={l}>{l}{l === 'S1' ? ' (düşük — önerilen)' : l === 'S3' ? ' (agresif)' : ' (dengeli)'}</option>)}
            </select>
            {levelCap && <div style={{ fontSize: 11, color: '#64748b', marginTop: 4 }}>varsayılan cap: {levelCap.capCalls} çağrı · {levelCap.capSec}s · ${levelCap.capCostUsd}</div>}
          </div>
          <div>
            <label style={lbl}>Cap: çağrı üst sınırı (boş = varsayılan)</label>
            <input style={{ ...inp, width: 120 }} value={capCalls} onChange={(e) => setCapCalls(e.target.value.replace(/[^0-9]/g, ''))} placeholder={String(levelCap?.capCalls ?? '')} />
          </div>
          <div>
            <label style={lbl}>Mod</label>
            <label style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 13, color: '#e2e8f0', paddingTop: 6 }}>
              <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} /> dry-run (maliyet yok — zinciri doğrula)
            </label>
          </div>
        </div>

        {/* Model yönetimi */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <label style={lbl}>Ajan-rolü modelleri (varsayılan: maliyet-güvenli)</label>
            <button type="button" onClick={() => setAdvanced((a) => !a)} style={{ ...inp, cursor: 'pointer', fontSize: 12 }}>{advanced ? 'gizle' : 'tümünü göster'}</button>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(200px,1fr))', gap: 8, marginTop: 6 }}>
            {(cat.roles as string[]).filter((r) => advanced || ['primary_agent', 'pentester', 'generator', 'coder'].includes(r)).map((role) => (
              <div key={role}>
                <label style={{ ...lbl, marginBottom: 2 }}>{role}</label>
                <select style={{ ...inp, width: '100%' }} value={models[role] ?? cat.defaults[role]} onChange={(e) => setModels((m) => ({ ...m, [role]: e.target.value }))}>
                  {cat.catalog.map((mo: any) => <option key={mo.id} value={mo.id}>{mo.label}</option>)}
                </select>
              </div>
            ))}
          </div>
        </div>

        {/* Maliyet tahmini */}
        {est && (
          <div style={{ padding: 12, borderRadius: 8, background: est.hasOpus ? '#3b0764' : '#0f172a', border: '1px solid #334155' }}>
            <div style={{ fontSize: 15, fontWeight: 700, color: '#e2e8f0' }}>Tahmini maliyet: ~${est.estUsd}</div>
            <div style={{ fontSize: 12, color: est.hasOpus ? '#f0abfc' : '#94a3b8', marginTop: 4 }}>{est.note}</div>
            <div style={{ fontSize: 11, color: '#64748b', marginTop: 4 }}>dominant model: {est.dominantModel}</div>
          </div>
        )}

        {error && <p style={{ color: '#fca5a5', fontSize: 13 }}>{error}</p>}
        <button onClick={start} disabled={busy}
          style={{ padding: '10px 18px', borderRadius: 8, border: 'none', background: dryRun ? '#0369a1' : '#b91c1c', color: '#fff', fontWeight: 700, cursor: 'pointer', fontSize: 14 }}>
          {busy ? '…' : dryRun ? '▶ Dry-run başlat (maliyet yok)' : '⚠ CANLI koşuyu başlat'}
        </button>
      </div>
    </>
  );
}
