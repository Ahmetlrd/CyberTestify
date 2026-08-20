/**
 * (3b-ii) Gözlemlenebilirlik DB katmanı — puller çıktısını RedTeamJob + RedTeamJobLog'a yazar.
 * Secret zaten puller'da maskelendi; burada da mesajlar maskeSecrets'ten geçer (çift kemer).
 */
import { prisma } from '../db.js';
import { maskSecrets, type PullResult, type PullLogLine } from './puller.js';
import type { StepLog } from './orchestrator.js';

/** Job'a özel bir sonraki log sırası. */
async function nextSeq(jobId: string): Promise<number> {
  const last = await prisma.redTeamJobLog.findFirst({ where: { jobId }, orderBy: { seq: 'desc' }, select: { seq: true } });
  return (last?.seq ?? 0) + 1;
}

/** Log satırlarını sırayla ekle (maskeli). */
export async function appendLogs(jobId: string, lines: PullLogLine[]): Promise<void> {
  if (!lines.length) return;
  let seq = await nextSeq(jobId);
  await prisma.redTeamJobLog.createMany({
    data: lines.map((l) => ({
      jobId, seq: seq++, source: l.source, level: l.level, message: maskSecrets(l.message).slice(0, 2000),
    })),
  });
}

/**
 * Orchestrator'ın her adımını (onStep) kalıcılaştır: faz güncelle + log ekle. Canlı runner
 * `runPipeline({ ..., onStep: (s) => persistStep(job.id, s) })` ile bunu bağlar → admin panelde
 * faz + adım logları canlı akar. Komut secret içerebilir → maskelenir.
 */
export async function persistStep(jobId: string, step: StepLog): Promise<void> {
  await prisma.redTeamJob.update({ where: { id: jobId }, data: { phase: step.phase } });
  const cmd = step.command ? maskSecrets(step.command) + ' — ' : '';
  await appendLogs(jobId, [
    { source: 'orchestrator', level: step.ok ? 'info' : 'error', message: `[${step.phase}] ${cmd}${step.detail}` },
  ]);
}

/** Pull sonucunu kalıcılaştır: canlı alanları güncelle + log satırlarını ekle. */
export async function persistPull(jobId: string, result: PullResult, phase?: string): Promise<void> {
  const { live } = result;
  await prisma.redTeamJob.update({
    where: { id: jobId },
    data: {
      ...(phase ? { phase } : {}),
      ...(live.llmCalls != null ? { llmCalls: live.llmCalls } : {}),
      ...(live.costUsd != null ? { costUsd: live.costUsd } : {}),
      ...(live.egressTargetOk != null ? { egressTargetOk: live.egressTargetOk } : {}),
      ...(live.egressCyberBlocked != null ? { egressCyberBlocked: live.egressCyberBlocked } : {}),
      ...(live.modelUsage ? { modelUsage: live.modelUsage as any } : {}),
      lastPulledAt: new Date(),
    },
  });
  await appendLogs(jobId, result.logs);
}
