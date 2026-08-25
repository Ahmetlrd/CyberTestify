import { collectLoginBypassEvidence } from './services/authExtraChecks.js';
(async () => {
  for (const loc of ['tr','de','en'] as const) {
    const ev = await collectLoginBypassEvidence('example.com', undefined, loc);
    console.log(`[${loc}] ok=${ev.ok} probes=${ev.probesSent} findings=${ev.findings.length}`);
    ev.notes.forEach(n => console.log(`   note: ${n.slice(0,90)}`));
  }
})().catch(e => { console.error('ERR', e); process.exit(1); });
