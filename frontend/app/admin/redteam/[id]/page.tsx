'use client';

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { adminApi } from '../../../../lib/adminApi';
import { H1, card, fmtDate } from '../../../../components/admin/ui';

const PHASES = ['guard', 'provision', 'setup', 'harden', 'verify', 'campaign', 'bind', 'report', 'teardown'];
const LOG_COLOR: Record<string, string> = { error: '#fca5a5', warn: '#fcd34d', info: '#cbd5e1' };
const SRC_COLOR: Record<string, string> = { pentagi: '#38bdf8', cap: '#fbbf24', audit: '#a3e635', egress: '#f472b6', killswitch: '#f87171', orchestrator: '#c4b5fd', puller: '#94a3b8' };

function Bar({ label, value, max, unit }: { label: string; value: number | null | undefined; max: number | null | undefined; unit: string }) {
  const v = value ?? 0;
  const m = max ?? 0;
  const pct = m > 0 ? Math.min(100, Math.round((v / m) * 100)) : 0;
  const col = pct >= 90 ? '#ef4444' : pct >= 70 ? '#f59e0b' : '#38bdf8';
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: '#94a3b8' }}>
        <span>{label}</span><span>{v}{unit} / {m || '?'}{unit}</span>
      </div>
      <div style={{ height: 8, background: '#0f172a', borderRadius: 999, overflow: 'hidden', marginTop: 3 }}>
        <div style={{ width: `${pct}%`, height: '100%', background: col, transition: 'width .4s' }} />
      </div>
    </div>
  );
}

function TierPill({ tier }: { tier: string }) {
  const m: Record<string, [string, string]> = { KANITLI: ['#22c55e', 'KANITLI'], BELIRSIZ: ['#f59e0b', 'BELİRSİZ'], HAYALET: ['#64748b', 'HAYALET'] };
  const [c, l] = m[tier] ?? ['#94a3b8', tier];
  return <span style={{ padding: '1px 7px', borderRadius: 999, fontSize: 11, fontWeight: 700, color: '#0f172a', background: c }}>{l}</span>;
}

export default function AdminRedTeamDetail({ params }: { params: { id: string } }) {
  const [job, setJob] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [logs, setLogs] = useState<any[]>([]);
  const [killing, setKilling] = useState(false);
  const lastSeq = useRef(0);

  useEffect(() => {
    const loadJob = () => adminApi.redteamJob(params.id).then(setJob).catch((e) => setError(e.message));
    const loadLogs = () =>
      adminApi.redteamJobLogs(params.id, lastSeq.current).then((d) => {
        if (d.logs.length) {
          lastSeq.current = d.logs[d.logs.length - 1].seq;
          setLogs((prev) => [...prev, ...d.logs]);
        }
      }).catch(() => {});
    loadJob(); loadLogs();
    const t = setInterval(() => { loadJob(); loadLogs(); }, 4000); // canlı polling
    return () => clearInterval(t);
  }, [params.id]);

  async function openReport(kind: 'html' | 'pdf') {
    try {
      const blob = await adminApi.redteamReportBlob(params.id, kind);
      const url = URL.createObjectURL(blob);
      if (kind === 'pdf') {
        const a = document.createElement('a');
        a.href = url;
        a.download = `redteam-${params.id.slice(0, 8)}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
      } else {
        window.open(url, '_blank');
      }
    } catch (e) {
      alert((e as Error).message);
    }
  }

  async function kill() {
    if (!confirm('KILL-SWITCH: ajanı durdur + egress kes. Emin misiniz?')) return;
    setKilling(true);
    try {
      const r = await adminApi.redteamKill(params.id);
      alert(r.ok ? 'Kill-switch tetiklendi.' : 'Kill-switch HATA: ' + r.output);
    } catch (e) {
      alert((e as Error).message);
    } finally {
      setKilling(false);
    }
  }

  if (error) return <><H1>Red Team İşi</H1><p style={{ color: '#fca5a5' }}>{error}</p></>;
  if (!job) return <><H1>Red Team İşi</H1><p style={{ color: '#94a3b8' }}>Yükleniyor…</p></>;

  const report = job.reportJson as any;
  const cap = job.cap as any;
  const active = !['completed', 'failed', 'torn_down'].includes(job.status);

  return (
    <>
      <Link href="/admin/redteam" style={{ color: '#94a3b8', fontSize: 13 }}>← Red Team</Link>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
        <H1>{job.domain} <span style={{ fontSize: 13, color: '#94a3b8', fontWeight: 400 }}>· {job.level} · {job.environment}</span></H1>
        {active && (
          <button onClick={kill} disabled={killing}
            style={{ padding: '8px 16px', borderRadius: 8, border: '1px solid #7f1d1d', background: '#450a0a', color: '#fca5a5', fontWeight: 700, cursor: 'pointer' }}>
            {killing ? '…' : '⛔ KILL-SWITCH'}
          </button>
        )}
      </div>

      {/* Faz göstergesi */}
      <div style={{ ...card, display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 14 }}>
        {PHASES.map((p) => {
          const cur = job.phase === p;
          const done = PHASES.indexOf(job.phase) > PHASES.indexOf(p) && job.phase;
          return (
            <span key={p} style={{
              padding: '4px 10px', borderRadius: 999, fontSize: 12, fontWeight: cur ? 700 : 500,
              background: cur ? '#38bdf8' : done ? '#14532d' : '#0f172a',
              color: cur ? '#0f172a' : done ? '#86efac' : '#64748b', border: '1px solid #334155',
            }}>{p}</span>
          );
        })}
        <span style={{ marginLeft: 'auto', fontSize: 13, color: '#e2e8f0' }}>durum: <b>{job.status}</b></span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(240px,1fr))', gap: 14 }}>
        {/* Cap metresi */}
        <div style={card}>
          <h3 style={{ fontSize: 14, margin: '0 0 10px', color: '#e2e8f0' }}>Cap metresi (sert tavan)</h3>
          <Bar label="LLM çağrısı" value={job.llmCalls} max={cap?.capCalls} unit="" />
          <Bar label="Süre" value={job.elapsedSec} max={cap?.capSec} unit="s" />
          <Bar label="Maliyet" value={job.costUsd} max={cap?.capCostUsd} unit="$" />
        </div>

        {/* Egress durumu */}
        <div style={card}>
          <h3 style={{ fontSize: 14, margin: '0 0 10px', color: '#e2e8f0' }}>Egress izolasyonu</h3>
          <p style={{ fontSize: 13, color: '#cbd5e1', margin: '4px 0' }}>
            Hedef erişilir: {job.egressTargetOk === true ? <b style={{ color: '#86efac' }}>✓ evet</b> : job.egressTargetOk === false ? <b style={{ color: '#fca5a5' }}>✗ hayır</b> : '—'}
          </p>
          <p style={{ fontSize: 13, color: '#cbd5e1', margin: '4px 0' }}>
            CyberTestify BLOCKED: {job.egressCyberBlocked === true ? <b style={{ color: '#86efac' }}>✓ izole</b> : job.egressCyberBlocked === false ? <b style={{ color: '#fca5a5' }}>⚠ SIZINTI!</b> : '—'}
          </p>
          <p style={{ fontSize: 11, color: '#64748b', marginTop: 8 }}>Hedef IP: {job.targetIp || '—'} · droplet: {job.dropletIp || '—'} · son pull: {fmtDate(job.lastPulledAt)}</p>
        </div>

        {/* Model dağılımı + maliyet */}
        <div style={card}>
          <h3 style={{ fontSize: 14, margin: '0 0 10px', color: '#e2e8f0' }}>Model dağılımı + maliyet</h3>
          {job.estCostUsd != null && <p style={{ fontSize: 12, color: '#94a3b8', margin: '0 0 6px' }}>tahmini: ~${Number(job.estCostUsd).toFixed(3)}{job.costUsd != null && ` · gerçek: $${Number(job.costUsd).toFixed(4)}`}</p>}
          {Array.isArray(job.modelUsage) && job.modelUsage.length ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
              {job.modelUsage.map((m: any, i: number) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: '#cbd5e1' }}>
                  <span style={{ color: '#c4b5fd' }}>{m.model}</span>
                  <span>{m.calls} çağrı · <b>${Number(m.costUsd).toFixed(4)}</b></span>
                </div>
              ))}
            </div>
          ) : <p style={{ fontSize: 12, color: '#64748b' }}>Model kullanımı koşu sırasında (canlı) dolar.</p>}
        </div>

        {/* Bulgular */}
        <div style={card}>
          <h3 style={{ fontSize: 14, margin: '0 0 10px', color: '#e2e8f0' }}>Bulgular</h3>
          {report ? (
            <>
              <p style={{ fontSize: 13, color: '#cbd5e1' }}>
                Genel risk: <b>{report.overallRisk}</b> · kanıtlı {report.counts?.kanitli ?? 0} · belirsiz {report.counts?.belirsiz ?? 0} · elenen {report.eliminated ?? 0}
              </p>
              <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 6 }}>
                {[...(report.proven || []).map((f: any) => ({ ...f, tier: 'KANITLI' })), ...(report.needsReview || []).map((f: any) => ({ ...f, tier: 'BELIRSIZ' }))].map((f: any, i: number) => (
                  <div key={i} style={{ fontSize: 12, color: '#cbd5e1' }}>
                    <TierPill tier={f.tier} /> {f.title} <span style={{ color: '#64748b' }}>({f.category}/{f.severity})</span>
                    {f.evidence && <div style={{ color: '#64748b', paddingLeft: 8 }}>↳ {f.evidence.detail} [{f.evidence.artifactRef}]</div>}
                  </div>
                ))}
              </div>
              <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
                <button onClick={() => openReport('html')} style={{ padding: '5px 12px', borderRadius: 6, border: '1px solid #334155', background: '#0f172a', color: '#7dd3fc', cursor: 'pointer', fontSize: 12 }}>Raporu Gör</button>
                <button onClick={() => openReport('pdf')} style={{ padding: '5px 12px', borderRadius: 6, border: '1px solid #334155', background: '#0f172a', color: '#a3e635', cursor: 'pointer', fontSize: 12 }}>PDF indir</button>
              </div>
            </>
          ) : <p style={{ fontSize: 13, color: '#64748b' }}>Henüz rapor yok (koşu tamamlanınca sınıflandırma gelir).</p>}
        </div>
      </div>

      {/* Canlı log akışı */}
      <section style={{ marginTop: 18 }}>
        <h3 style={{ fontSize: 14, color: '#e2e8f0', margin: '0 0 8px' }}>Canlı log akışı {active && <span style={{ fontSize: 11, color: '#38bdf8' }}>● canlı</span>}</h3>
        <div style={{ ...card, fontFamily: 'ui-monospace,Menlo,monospace', fontSize: 12, maxHeight: 380, overflowY: 'auto', background: '#0b1120' }}>
          {logs.length === 0 ? <span style={{ color: '#64748b' }}>Log yok (canlı koşu sırasında dolacak).</span> : logs.map((l) => (
            <div key={l.seq} style={{ padding: '2px 0', borderBottom: '1px solid #16233a' }}>
              <span style={{ color: '#475569' }}>{new Date(l.at).toLocaleTimeString('tr-TR')} </span>
              <span style={{ color: SRC_COLOR[l.source] ?? '#94a3b8', fontWeight: 600 }}>[{l.source}]</span>{' '}
              <span style={{ color: LOG_COLOR[l.level] ?? '#cbd5e1' }}>{l.message}</span>
            </div>
          ))}
        </div>
      </section>

      <p style={{ fontSize: 12, color: '#64748b', marginTop: 14 }}>
        Oluşturma {fmtDate(job.createdAt)} · başlangıç {fmtDate(job.startedAt)} · bitiş {fmtDate(job.finishedAt)}
        {job.costUsd != null && ` · maliyet ~$${Number(job.costUsd).toFixed(4)}`}
        {job.error && <span style={{ color: '#fca5a5' }}> · hata: {job.error}</span>}
      </p>
    </>
  );
}
