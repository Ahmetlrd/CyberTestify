/**
 * (LINKEDIN KAMPANYASI — 30 GONDERI / 2026-09-08 → 2026-11-10)
 *
 * 14 gonderi, haftada 3-4. Format karisimi: 6 natif PDF carousel (%43), 5 gorsel, 3 metin.
 * Gun/saat: tercihen Sali/Carsamba/Persembe (iki hafta 4'e cikarmak icin birer Pazartesi),
 * 09:30 / 10:30 / 14:30 Turkiye saati (UTC+3) -> UTC olarak yazilir.
 *
 * TEK KAYNAK: buradaki tanim hem PDF/gorsel uretimini hem Buffer zamanlamasini besler.
 * Yeniden calistirmak icin: scripts/queueLinkedinCampaign.ts
 */
import type { Slide } from '../services/linkedinCarousel.js';
import { CAMPAIGN_EXTRA } from './linkedin2026_extra.js'; // EK 16 gonderi (Eki-Kas) — toplam 30

export type CampaignPost = {
  id: string;
  /** UTC ISO — Turkiye saati (UTC+3) ile yorumlanip donusturulmustur. */
  dueAtUtc: string;
  localTr: string;      // insan-okunur kontrol icin
  format: 'pdf' | 'image' | 'text';
  /** LinkedIn dokuman basligi (carousel ustunde gorunur) veya gorsel basligi. */
  mediaTitle?: string;
  text: string;
  slides?: Slide[];     // pdf: tum sayfalar | image: tek kare
};

const CTA = {
  soft: 'If you want a second opinion on any of this, our team runs external assessments — happy to point you in the right direction either way.',
};

export const CAMPAIGN: CampaignPost[] = [
  // ─────────────────────────────── HAFTA 1 ───────────────────────────────
  {
    id: 'p01-board-reporting',
    dueAtUtc: '2026-09-08T06:30:00.000Z', localTr: '08 Eyl Sal 09:30',
    format: 'pdf',
    mediaTitle: 'Security reporting your board will actually read',
    text: `Most board security decks fail for the same reason: they report activity, not exposure.

"We patched 1,400 vulnerabilities this quarter" tells a board nothing. It cannot be acted on, budgeted against, or compared to last quarter.

After reviewing how security leaders present risk upward, the ones who get funded share a pattern. They answer four questions on a single page:

1. What could stop the business tomorrow?
2. How exposed are we right now, in plain numbers?
3. What changed since last quarter — better or worse?
4. What do you need us to decide today?

Everything else is an appendix.

The carousel below breaks down a one-page board format, with the specific metrics that survive a CFO's follow-up question and the ones that don't.

A word of caution: none of this works if your underlying data is soft. A board metric built on an unvalidated scanner export will not survive its first serious challenge.

#CISO #CyberSecurity #SecurityLeadership #RiskManagement #BoardGovernance #InfoSec #CyberRisk`,
    slides: [
      { variant: 'cover', kicker: 'Board reporting', title: 'The one-page security report your board will actually read', body: 'Four questions. Real numbers. No activity metrics.' },
      { variant: 'content', kicker: 'The problem', title: 'Activity is not exposure', body: '"1,400 vulnerabilities patched" is a workload number. Boards fund **risk reduction**, not workload. If a metric cannot change a decision, it does not belong on the page.' },
      { variant: 'content', kicker: 'Question 1', title: 'What could stop the business tomorrow?', bullets: ['Name the 3–5 scenarios, not 300 findings', 'Tie each to a revenue or service impact', 'State whether it is **currently** possible, not theoretically possible'] },
      { variant: 'content', kicker: 'Question 2', title: 'How exposed are we, in plain numbers?', bullets: ['Internet-facing assets you own vs assets you knew about', 'Confirmed exploitable findings — not scanner counts', 'Mean time to remediate **critical** items'] },
      { variant: 'content', kicker: 'Question 3', title: 'What changed this quarter?', body: 'A single trend line beats a table. Boards remember direction, not decimals. Show the same three numbers every quarter so the shape of the trend becomes the message.' },
      { variant: 'content', kicker: 'Question 4', title: 'What do you need decided today?', bullets: ['One decision per slide, with the cost of saying no', 'Options, not ultimatums', 'A named owner and a date'] },
      { variant: 'content', kicker: 'Metrics that survive scrutiny', title: 'Keep these', bullets: ['Confirmed exploitable findings, open vs closed', 'External attack surface: known vs discovered', 'Third-party access still active after offboarding', 'Time to detect in the last exercise'] },
      { variant: 'content', kicker: 'Metrics that get you challenged', title: 'Cut these', bullets: ['Raw vulnerability counts with no validation', 'Phishing click-rate with no follow-through', 'Tool coverage percentages', 'Anything you cannot explain in one sentence'] },
      { variant: 'content', kicker: 'The failure mode', title: 'Soft data breaks good slides', body: 'A metric built on an unvalidated scanner export will not survive its first serious challenge. If a number reaches the board, someone should be able to show the evidence behind it.' },
      { variant: 'cta', title: 'Report exposure, not effort', body: 'If your current reporting rests on unvalidated data, that is the thing to fix first — before the format.' },
    ],
  },
  {
    id: 'p02-attack-surface-drift',
    dueAtUtc: '2026-09-09T07:30:00.000Z', localTr: '09 Eyl Çar 10:30',
    format: 'image',
    mediaTitle: 'Five ways your attack surface grows without approval',
    text: `Your attack surface does not grow because someone approved it. It grows because someone was in a hurry.

Five patterns we see repeatedly on external assessments:

→ A staging environment that was never taken down, still resolving, still indexed.
→ A subdomain pointing at a cloud resource that no longer exists — free to claim by anyone who notices.
→ An API endpoint shipped for a mobile release, still live two versions later.
→ A vendor-hosted portal on your domain that your team has no console access to.
→ A backup file left in a web root during a migration that finished eighteen months ago.

None of these appear in a change ticket. None of them show up in an internal asset inventory. All of them are reachable from the internet right now.

The uncomfortable part: most organisations discover these through an external scan, not through their own records. If your inventory and your DNS disagree, your DNS is telling the truth.

Worth asking your team this week: when did we last enumerate what we actually expose — not what we think we expose?

#AttackSurface #CyberSecurity #CISO #InfoSec #CloudSecurity #ShadowIT #RiskManagement`,
    slides: [{ variant: 'cover', kicker: 'External exposure', title: '5 ways your attack surface grows without approval', bullets: ['Staging that never came down', 'Dangling DNS to deleted cloud assets', 'API endpoints outliving their release', 'Vendor portals on your domain', 'Backup files left in a web root'] }],
  },
  {
    id: 'p03-no-findings',
    dueAtUtc: '2026-09-10T11:30:00.000Z', localTr: '10 Eyl Per 14:30',
    format: 'text',
    text: `"No findings" is the most misread sentence in security reporting.

It does not mean you are secure. It means a defined set of techniques, run against a defined scope, in a defined window, produced no evidence.

Change any one of those three and the result can change with it.

So when a report comes back clean, the useful question is not "are we safe?" It is:

— What exactly was tested, by name?
— What was explicitly out of scope, and why?
— Which checks ran but could not reach a testable surface?
— What would have counted as evidence if it existed?

A report that cannot answer those four questions has not proven anything. It has only failed to find something, which is a very different claim.

The strongest reports we see are the ones honest enough to say "this control ran and found nothing" separately from "this control could not run at all." Those two outcomes look identical in a summary table and mean completely opposite things.

If your last assessment came back clean, pull it up and check whether it distinguishes between them.

#PenetrationTesting #CyberSecurity #CISO #InfoSec #SecurityTesting #RiskManagement #VulnerabilityManagement`,
  },

  // ─────────────────────────────── HAFTA 2 ───────────────────────────────
  {
    id: 'p04-vendor-risk',
    dueAtUtc: '2026-09-14T06:30:00.000Z', localTr: '14 Eyl Pzt 09:30',
    format: 'pdf',
    mediaTitle: 'Third-party risk: 10 questions that actually filter vendors',
    text: `Most vendor security questionnaires are 200 questions long and filter nobody.

They get forwarded to a sales engineer, answered from a template, and filed. Everyone completes the process. Nobody learns anything.

Ten questions do more work than two hundred — because they are hard to answer from a template and easy to verify afterwards.

A few of them:

→ Which of your subprocessors can reach our data, and how do we find out when that list changes?
→ When an employee of yours leaves, how long does their access to our tenant survive?
→ Show me the last time you restored from backup, not the policy that says you can.

The carousel below has all ten, plus what a good answer looks like versus an answer that is technically true and practically useless.

One thing worth saying plainly: a SOC 2 report is evidence that a process existed during an observation window. It is not evidence that the control is working in your environment today. Read the exceptions section — that is where the information is.

#ThirdPartyRisk #VendorRisk #CISO #CyberSecurity #SupplyChainSecurity #Compliance #RiskManagement #InfoSec`,
    slides: [
      { variant: 'cover', kicker: 'Third-party risk', title: '10 questions that actually filter vendors', body: 'Hard to answer from a template. Easy to verify later.' },
      { variant: 'content', kicker: 'Why 200 questions fail', title: 'Templates answer templates', body: 'Long questionnaires reward the vendors with the best documentation team, not the best security. The goal is not coverage — it is **discrimination** between vendors.' },
      { variant: 'content', kicker: '01 – 03', title: 'Access and data', bullets: ['Which subprocessors can reach our data, and how are we told when that list changes?', 'What is the maximum retention of our data after contract termination?', 'Which of your staff can access our tenant without our approval?'] },
      { variant: 'content', kicker: '04 – 06', title: 'Identity and offboarding', bullets: ['When your employee leaves, how long does access to our tenant survive?', 'Is MFA enforced for every administrative path, including break-glass?', 'How do you detect a compromised employee account — and how fast?'] },
      { variant: 'content', kicker: '07 – 08', title: 'Resilience — evidence, not policy', bullets: ['Show the last restore you performed, with a date', 'What is your longest unplanned outage in the past 24 months, and what caused it?'] },
      { variant: 'content', kicker: '09 – 10', title: 'Assurance and disclosure', bullets: ['When was your last external test, what scope, and may we see the summary?', 'What is your notification window to us after a confirmed incident — in hours?'] },
      { variant: 'content', kicker: 'Reading the answers', title: 'Good vs technically true', body: '"We follow industry best practice" is not an answer. "Access is revoked by an automated job within 4 hours; here is last month\'s exception report" is. Ask for artefacts, not adjectives.' },
      { variant: 'content', kicker: 'On certifications', title: 'What a SOC 2 does and does not tell you', bullets: ['It shows a process existed during an observation window', 'It does not show the control works in **your** tenant today', 'The exceptions section carries the real signal', 'Check the scope boundary — often narrower than the product'] },
      { variant: 'cta', title: 'Fewer questions. Better answers.', body: 'Ask for evidence you could verify independently. If a vendor cannot produce it, that is your finding.' },
    ],
  },
  {
    id: 'p05-cloud-misconfig',
    dueAtUtc: '2026-09-15T07:30:00.000Z', localTr: '15 Eyl Sal 10:30',
    format: 'image',
    mediaTitle: 'Six cloud misconfigurations behind most avoidable incidents',
    text: `Cloud breaches are rarely exotic. They are usually one of six configurations, left in place by someone who meant to come back to it.

→ Storage set to public during a migration and never reverted
→ An over-permissive IAM role attached to a compute instance, reachable from a web application
→ Metadata service accessible to an app that accepts user-supplied URLs
→ Security group opened to 0.0.0.0/0 "temporarily" for a debugging session
→ Logging disabled in a region nobody thinks about
→ Long-lived access keys in a repository that turned public two owners ago

What these have in common: each one was created by a person solving a real problem under time pressure. None was malicious. All are still exploitable.

The practical move is not a new tool. It is a standing question in your change process: what did we open, and when does it close?

Configuration drift is not a technology failure. It is an unclosed loop.

#CloudSecurity #CyberSecurity #CISO #DevSecOps #InfoSec #AWS #RiskManagement`,
    slides: [{ variant: 'cover', kicker: 'Cloud exposure', title: '6 misconfigurations behind most avoidable cloud incidents', bullets: ['Public storage after a migration', 'Over-permissive instance IAM roles', 'Reachable metadata service', 'Security group open to the world', 'Logging off in a forgotten region', 'Long-lived keys in a public repo'] }],
  },
  {
    id: 'p06-ransomware-readiness',
    dueAtUtc: '2026-09-16T06:30:00.000Z', localTr: '16 Eyl Çar 09:30',
    format: 'pdf',
    mediaTitle: 'Ransomware readiness: 12 checks to run before you need them',
    text: `Ransomware readiness is not a product decision. It is a set of assumptions that have never been tested.

Every organisation believes it can restore. Far fewer have restored a production system, end to end, with the person who normally does it on holiday.

Twelve checks worth running before an incident forces the issue:

The first three alone separate most organisations:

1. Restore one business-critical system from backup, to a clean environment, and time it.
2. Verify your backups are unreachable from a compromised domain admin account.
3. Confirm your incident contact list works outside your own email and network.

That third one catches people. If your runbook lives on the file share that just got encrypted, you do not have a runbook.

The carousel has all twelve, grouped into prevention, containment and recovery — with the specific failure each one is designed to surface.

None of this requires new spend. It requires a scheduled afternoon and permission to find out something uncomfortable.

#Ransomware #IncidentResponse #CISO #CyberSecurity #BusinessContinuity #InfoSec #RiskManagement #Resilience`,
    slides: [
      { variant: 'cover', kicker: 'Readiness', title: '12 ransomware checks to run before you need them', body: 'Not a product decision. A set of untested assumptions.' },
      { variant: 'content', kicker: 'The core problem', title: 'Everyone believes they can restore', body: 'Belief is not evidence. The gap between "we have backups" and "we have restored a production system under pressure" is where most recovery plans fail.' },
      { variant: 'content', kicker: 'Prevention 01–03', title: 'Reduce the entry paths', bullets: ['MFA on every remote access path, including legacy and vendor accounts', 'No local admin rights for standard users — verify, do not assume', 'External RDP and management interfaces: confirm none are reachable'] },
      { variant: 'content', kicker: 'Prevention 04–05', title: 'Limit the blast radius', bullets: ['Tiered administration: a workstation admin cannot reach domain controllers', 'Segment backup infrastructure onto separate credentials **and** separate identity'] },
      { variant: 'content', kicker: 'Containment 06–08', title: 'Can you actually stop it?', bullets: ['Time how long it takes to isolate a single host — measured, not estimated', 'Confirm you can disable a compromised account across all systems, not just AD', 'Verify EDR alerts reach a human out of hours'] },
      { variant: 'content', kicker: 'Recovery 09–10', title: 'The restore test', bullets: ['Restore one business-critical system to a clean environment and record the time', 'Do it with the primary owner unavailable — the process must survive absence'] },
      { variant: 'content', kicker: 'Recovery 11', title: 'Are your backups actually out of reach?', body: 'Assume a compromised domain admin. Can that identity delete, encrypt or alter retention on your backups? If yes, your backups are part of the attack surface, not the recovery plan.' },
      { variant: 'content', kicker: 'Recovery 12', title: 'The runbook that survives the network', body: 'Incident contacts, escalation paths and vendor numbers must be reachable without your email, your file share or your VPN. Print it. Test it from a personal device.' },
      { variant: 'content', kicker: 'How to run this', title: 'One afternoon, one honest scorecard', bullets: ['Score each check: verified / assumed / unknown', 'Anything marked "assumed" is the real backlog', 'Re-run after every material infrastructure change'] },
      { variant: 'cta', title: 'Find out on a Tuesday, not at 3am', body: 'The purpose of a readiness check is to be disappointed cheaply, while there is still time to fix it.' },
    ],
  },

  {
    id: 'p07-surface-vs-pentest',
    dueAtUtc: '2026-09-17T11:30:00.000Z', localTr: '17 Eyl Per 14:30',
    format: 'text',
    text: `A pentest scope and an attack surface are two different things, and the gap between them is where incidents happen.

The scope is what you agreed to test. The attack surface is what an attacker can reach. Those overlap far less than most teams assume.

A typical mismatch looks like this: the assessment covers the main application and its API. Meanwhile the same organisation exposes a marketing site on a vendor platform, a legacy portal on a subdomain nobody owns anymore, and a staging instance that answers on a non-standard port.

None of that was in scope. All of it is in reach.

Two practices close the gap:

First, enumerate before you scope. Discovery should come from DNS, certificate transparency and your own cloud accounts — not from the asset list someone maintains by hand. If your inventory and your certificate logs disagree, trust the certificate logs.

Second, scope explicitly to what you found, and write down what you deliberately excluded. An exclusion you documented is a risk decision. An exclusion you never noticed is a blind spot.

The report you receive can only be as complete as the scope you handed over. That part is on the buyer, not the tester.

#PenetrationTesting #AttackSurface #CISO #CyberSecurity #InfoSec #RiskManagement #SecurityTesting`,
  },

  // ─────────────────────────────── HAFTA 3 ───────────────────────────────
  {
    id: 'p08-testing-decision-guide',
    dueAtUtc: '2026-09-22T06:30:00.000Z', localTr: '22 Eyl Sal 09:30',
    format: 'pdf',
    mediaTitle: 'Scan, pentest or red team — a decision guide',
    text: `"We need a pentest" is often the wrong starting sentence.

Sometimes the honest answer is a vulnerability scan. Sometimes it is a red team exercise. Buying the wrong one wastes budget and, worse, produces a document that answers a question nobody asked.

The distinction is not depth. It is the question each one answers:

→ A scan answers: what known weaknesses exist across our estate?
→ A pentest answers: can these weaknesses actually be exploited, and what do they reach?
→ A red team answers: would we notice, and could we stop it?

If your detection capability has never been tested, a red team will tell you more than another pentest will. If you have never enumerated your external estate, a scan will tell you more than either.

The carousel below maps each option to the situation it fits, what you get, what you do not, and the maturity signals that tell you which one you are ready for.

One caution: red team results are only meaningful if you have a blue team to measure. Running one before you have detection in place produces an expensive report confirming what you already suspected.

#PenetrationTesting #RedTeam #CISO #CyberSecurity #SecurityTesting #InfoSec #VulnerabilityManagement #SecurityLeadership`,
    slides: [
      { variant: 'cover', kicker: 'Decision guide', title: 'Scan, pentest or red team?', body: 'Not a question of depth. A question of what you need to learn.' },
      { variant: 'content', kicker: 'The framing', title: 'Each answers a different question', bullets: ['**Scan:** what known weaknesses exist?', '**Pentest:** can they be exploited, and what do they reach?', '**Red team:** would we notice, and could we stop it?'] },
      { variant: 'content', kicker: 'Vulnerability scan', title: 'Breadth, fast, repeatable', bullets: ['Best when: your inventory is incomplete or changes weekly', 'You get: coverage and trend over time', 'You do not get: proof that anything is exploitable', 'Cadence: continuous or monthly'] },
      { variant: 'content', kicker: 'Penetration test', title: 'Proof, on a defined scope', bullets: ['Best when: you need to know what is actually reachable', 'You get: validated findings with evidence and business impact', 'You do not get: an answer about your detection capability', 'Cadence: per major release, or annually plus changes'] },
      { variant: 'content', kicker: 'Red team', title: 'Tests the defenders, not the code', bullets: ['Best when: detection and response are already in place', 'You get: measured time to detect, contain and escalate', 'You do not get: comprehensive coverage — it follows one path', 'Cadence: annually, once maturity supports it'] },
      { variant: 'content', kicker: 'Readiness check', title: 'Which one are you ready for?', bullets: ['No reliable asset inventory → start with discovery and scanning', 'Inventory solid, findings unvalidated → pentest', 'Findings handled, detection untested → red team', 'No SOC or on-call → not yet a red team'] },
      { variant: 'content', kicker: 'Common mistake', title: 'Buying depth before breadth', body: 'A deep test of one application, while three forgotten hosts sit exposed, optimises the wrong variable. Enumerate first; go deep second.' },
      { variant: 'content', kicker: 'What to ask any provider', title: 'Four questions before you sign', bullets: ['What exactly will be in scope — by hostname?', 'Will findings be validated, or reported as scanner output?', 'What evidence accompanies each finding?', 'What will the report say about what you could **not** test?'] },
      { variant: 'cta', title: 'Match the method to the question', body: 'The best assessment is the one that changes a decision. If the output would not change anything, buy something else.' },
    ],
  },
  {
    id: 'p09-email-spoofing',
    dueAtUtc: '2026-09-23T07:30:00.000Z', localTr: '23 Eyl Çar 10:30',
    format: 'image',
    mediaTitle: 'Can anyone send email as your domain?',
    text: `Here is a check that takes four minutes and occasionally ruins someone's afternoon.

Look up your domain's SPF, DKIM and DMARC records. Then read the DMARC policy specifically.

If it says p=none, your domain has no enforcement. Anyone can send mail that appears to come from you, and receiving servers are being told to deliver it anyway.

p=none is a monitoring mode. It exists so you can collect reports before enforcing. The problem is that a lot of domains were set to p=none during a rollout in some previous year and quietly stayed there.

Three things worth knowing:

→ SPF alone does not stop display-name spoofing, and it breaks silently past ten DNS lookups.
→ DKIM proves the message was signed, but without DMARC nothing enforces alignment.
→ DMARC is where the enforcement decision actually lives — quarantine or reject.

This is one of the few security improvements that costs nothing, takes effect quickly, and directly reduces the most common initial access vector there is.

Check yours. If it says p=none, you now have a task for this week.

#EmailSecurity #DMARC #CyberSecurity #CISO #Phishing #InfoSec #RiskManagement`,
    slides: [{ variant: 'cover', kicker: 'Email spoofing', title: 'Can anyone send email as your domain?', bullets: ['**p=none** means no enforcement', 'SPF breaks silently past 10 DNS lookups', 'DKIM signs — DMARC enforces', 'A 4-minute check, done from your phone'] }],
  },
  {
    id: 'p10-first-90-days',
    dueAtUtc: '2026-09-24T06:30:00.000Z', localTr: '24 Eyl Per 09:30',
    format: 'pdf',
    mediaTitle: 'First 90 days as a security leader',
    text: `The fastest way to lose credibility in a new security role is to announce a strategy in week two.

You do not yet know which risks are real, which controls are theatre, and which processes people quietly work around. Anything you commit to now, you will spend the next year defending.

A pattern that works better, split across three phases:

Days 1–30: understand, do not change. Map what exists, who owns it, and what the business actually cannot afford to lose. Ask every team the same question: "what worries you that nobody is looking at?" You will get your real backlog from that one question.

Days 31–60: prove one thing. Pick a single visible, verifiable improvement and complete it. Credibility is built on a finished item, not a roadmap.

Days 61–90: now write the plan — grounded in what you found, priced, and sequenced.

The carousel breaks each phase into specific activities, the questions to ask, and the traps that catch new leaders. Including the biggest one: inheriting someone else's risk register without validating a single entry.

#CISO #SecurityLeadership #CyberSecurity #InfoSec #Leadership #RiskManagement #SecurityStrategy`,
    slides: [
      { variant: 'cover', kicker: 'New in the role', title: 'First 90 days as a security leader', body: 'Understand. Prove one thing. Then plan.' },
      { variant: 'content', kicker: 'The trap', title: 'Announcing strategy in week two', body: 'You do not yet know which risks are real, which controls are theatre, or which processes people work around. Whatever you commit to now, you will defend for a year.' },
      { variant: 'content', kicker: 'Days 1–30', title: 'Understand — change nothing', bullets: ['Map what exists and who actually owns it', 'Identify what the business cannot afford to lose, in their words', 'Ask every team: "what worries you that nobody is looking at?"', 'Sit in on one incident, even a small one'] },
      { variant: 'content', kicker: 'Days 1–30', title: 'Validate what you inherited', bullets: ['Take three entries from the risk register and test whether they are still true', 'Confirm the asset inventory against DNS and cloud accounts', 'Find out when the last restore test actually happened'] },
      { variant: 'content', kicker: 'Days 31–60', title: 'Prove one thing', body: 'Pick a single visible, verifiable improvement and finish it. Credibility comes from a completed item, not a roadmap. MFA on a forgotten access path is worth more than a strategy document.' },
      { variant: 'content', kicker: 'Days 31–60', title: 'Build the relationships that decide budgets', bullets: ['Finance: how security spend gets approved here', 'Legal: what contractual obligations already exist', 'Engineering: where security currently slows them down', 'Fix one of their problems before asking for anything'] },
      { variant: 'content', kicker: 'Days 61–90', title: 'Now write the plan', bullets: ['Grounded in what you verified, not what you assumed', 'Priced, sequenced, and tied to business outcomes', 'With one number you will report every quarter from now on'] },
      { variant: 'content', kicker: 'Traps', title: 'What catches new leaders', bullets: ['Inheriting a risk register without validating an entry', 'Buying tooling before knowing the gaps', 'Confusing compliance status with security posture', 'Making the first 90 days about the team you wish you had'] },
      { variant: 'cta', title: 'Earn the right to the roadmap', body: 'The plan lands better in month three, backed by findings, than in week two backed by assumptions.' },
    ],
  },

  {
    id: 'p11-security-headers',
    dueAtUtc: '2026-09-28T07:30:00.000Z', localTr: '28 Eyl Pzt 10:30',
    format: 'image',
    mediaTitle: 'Security headers: the four that matter',
    text: `Security header checklists tend to list a dozen headers and rank them all equally. In practice, four do most of the work — and one of them is doing something different from what most teams think.

Content-Security-Policy is the only one that meaningfully limits what a successful injection can do. It is also the only one that takes real effort to deploy, which is why it is usually the one missing.

Strict-Transport-Security removes the first-request downgrade window. Without it, that first plain HTTP request is still interceptable, no matter how good your TLS configuration is.

X-Frame-Options — or CSP frame-ancestors — stops your interface being framed and used against your own users.

X-Content-Type-Options is one line, has no downside, and closes a whole class of MIME confusion.

The others are worth having. These four change outcomes.

A caveat worth stating: headers are defence in depth, not a fix. A CSP does not repair an injection flaw; it limits what that flaw can accomplish. Treat a missing header as a hardening gap, not as the vulnerability itself.

#ApplicationSecurity #WebSecurity #CyberSecurity #DevSecOps #InfoSec #CISO #AppSec`,
    slides: [{ variant: 'cover', kicker: 'Hardening', title: 'Security headers: the four that change outcomes', bullets: ['**CSP** — limits what an injection can do', '**HSTS** — closes the first-request window', '**X-Frame-Options** — stops clickjacking', '**X-Content-Type-Options** — one line, no downside'] }],
  },
  {
    id: 'p12-compliance-vs-security',
    dueAtUtc: '2026-09-29T06:30:00.000Z', localTr: '29 Eyl Sal 09:30',
    format: 'text',
    text: `Compliance tells you a control existed on the day someone looked. Security is about whether it works on the day it matters.

That gap is not an argument against compliance. Frameworks are useful — they create a floor, a shared vocabulary, and a budget conversation that finance understands.

The failure is treating the certificate as the outcome.

Three places the gap shows up, consistently:

Scope. A certification covers a defined boundary. The systems outside that boundary are not less exposed — they are just not mentioned. Attackers do not read your scope statement.

Point in time. An audit observes a window. Configuration drifts the day after. The control that passed in March is not necessarily the control running in September, and nothing in the framework will tell you when it changed.

Evidence quality. A policy document proves intent. A screenshot proves a moment. Neither proves the control is operating. Frameworks accept all three as evidence; attackers only care about the third.

The practical test: pick one control you were certified against and try to verify it independently, today, without asking the team that owns it. What you find is your actual posture.

Compliance is the floor. It was never meant to be the ceiling.

#Compliance #CISO #CyberSecurity #RiskManagement #InfoSec #ISO27001 #SecurityLeadership`,
  },
  {
    id: 'p13-evidence-vs-noise',
    dueAtUtc: '2026-09-30T06:30:00.000Z', localTr: '30 Eyl Çar 09:30',
    format: 'pdf',
    mediaTitle: 'How to tell a real finding from noise',
    text: `The hardest part of a security report is not finding issues. It is deciding which ones are real.

A scanner will hand you 400 items. A good assessment hands you eleven and can defend every one. The difference is evidence.

Four questions separate a finding from noise:

1. What was observed — specifically? "Possible SQL injection" is a hypothesis. "Database error signature returned in the response to this payload" is an observation.
2. Can it be reproduced? A finding that only appeared once, in one session, needs to be labelled as such.
3. What does it actually reach? Severity without reachability is guesswork. An exploitable flaw on an isolated internal host is not the same as one on your login page.
4. What would disprove it? If nothing could, it is an opinion.

The carousel goes through each, with side-by-side examples of the same issue written as evidence versus written as noise.

Why this matters commercially: every false positive you pass to an engineering team costs credibility you will need later. Teams stop reading reports that waste their time — and then they miss the one that mattered.

#VulnerabilityManagement #PenetrationTesting #CyberSecurity #CISO #InfoSec #SecurityTesting #AppSec #RiskManagement`,
    slides: [
      { variant: 'cover', kicker: 'Signal vs noise', title: 'How to tell a real finding from noise', body: 'A scanner gives you 400 items. A good assessment gives you 11 it can defend.' },
      { variant: 'content', kicker: 'Question 1', title: 'What was observed, specifically?', body: '**Noise:** "Possible SQL injection detected."\n**Evidence:** "A database error signature was returned in the response to a single-quote payload on this parameter."' },
      { variant: 'content', kicker: 'Question 2', title: 'Can it be reproduced?', bullets: ['A one-time observation is a lead, not a finding', 'Repeat with a control request to rule out coincidence', 'If it is timing-based, say so — and say how confident that makes it'] },
      { variant: 'content', kicker: 'Question 3', title: 'What does it actually reach?', body: 'Severity without reachability is guesswork. The same flaw class on an isolated internal host and on your login page are not the same risk. Impact belongs in the finding, not in a generic table.' },
      { variant: 'content', kicker: 'Question 4', title: 'What would disprove it?', body: 'A claim that nothing could falsify is an opinion. Good findings state the condition under which they would be wrong — and confirm that condition was checked.' },
      { variant: 'content', kicker: 'The confidence label', title: 'Say how sure you are', bullets: ['**Direct evidence** — signature, returned data, reproduced behaviour', '**Indirect** — timing, inference, correlation', '**Observation only** — worth reviewing, not yet a finding', 'Mixing these three in one list destroys the list'] },
      { variant: 'content', kicker: 'The third state', title: '"Could not be tested" is not "clean"', body: 'A check that found nothing and a check that never ran look identical in a summary table and mean opposite things. Reports that merge them are hiding their own gaps.' },
      { variant: 'content', kicker: 'Why it matters', title: 'False positives cost credibility', body: 'Every unfounded finding you pass to engineering spends trust you will need for the one that matters. Teams stop reading reports that waste their time.' },
      { variant: 'cta', title: 'Fewer findings. Every one defensible.', body: 'If a finding cannot survive an engineer asking "how do you know?", it is not ready to be in the report.' },
    ],
  },
  {
    id: 'p14-pentest-questions',
    dueAtUtc: '2026-10-01T11:30:00.000Z', localTr: '01 Eki Per 14:30',
    format: 'image',
    mediaTitle: 'Seven questions to ask before your next pentest',
    text: `Most disappointing penetration tests were decided before the testing started — in the scoping call.

Seven questions that change what you receive:

→ How will scope be determined? If the answer is "send us your asset list", you are testing your own record-keeping, not your exposure.
→ Will findings be validated, or reported as tool output?
→ What evidence comes with each finding — and will an engineer be able to reproduce it?
→ How will you distinguish "checked and clean" from "could not be checked"?
→ What happens if you find something critical mid-engagement? Who gets called, how fast?
→ Will the report tell me what you were unable to test, explicitly?
→ Can I see a redacted sample report before I sign?

That last one is the highest-signal question in the list. A provider confident in their reporting will send one immediately. Ask for it every time.

The output of a test is not a list of vulnerabilities. It is a set of decisions you can now make. If the report does not enable a decision, it did not do its job.

#PenetrationTesting #CISO #CyberSecurity #SecurityTesting #InfoSec #Procurement #RiskManagement`,
    slides: [{ variant: 'cover', kicker: 'Before you sign', title: '7 questions to ask before your next pentest', bullets: ['How is scope actually determined?', 'Validated findings, or tool output?', 'What evidence comes with each finding?', '"Clean" vs "could not be tested"?', 'Escalation path for a critical find', 'Will you list what you could not test?', '**Can I see a redacted sample report?**'] }],
  },
  // ── EK KAMPANYA (Eki 6 – Kas 10) — 16 gonderi, ayni kalite/ton ──
  ...CAMPAIGN_EXTRA,
];
