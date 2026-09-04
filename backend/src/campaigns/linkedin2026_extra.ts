/**
 * (LINKEDIN KAMPANYASI — EK 16 GONDERI / 2026-10-06 → 2026-11-10)
 *
 * Mevcut 14 gonderiye (linkedin2026_09.ts) EK. Toplam 30 gonderi, ~2 ay, haftada 3-4.
 * Bu dosya: 10 PDF carousel + 4 gorsel + 2 metin (PDF-agirlikli). Ayni ton: somut, sifir dolgu,
 * soft-sell, CISO/guvenlik lideri seviyesi. Tum metin Ingilizce. Gun/saat: Sali/Carsamba/Persembe,
 * 09:30 / 10:30 / 14:30 Turkiye (UTC+3) -> UTC. TEK KAYNAK: CAMPAIGN (09) bunu spread ile birlestirir.
 */
import type { Slide } from '../services/linkedinCarousel.js';
import type { CampaignPost } from './linkedin2026_09.js';

const SOFT = `If any of this maps to a gap you already suspect, an external assessment is often the fastest way to confirm it — happy to point you in the right direction either way.`;

export const CAMPAIGN_EXTRA: CampaignPost[] = [
  // ─────────────────────────────── HAFTA 5 ───────────────────────────────
  {
    id: 'p15-cloud-misconfig',
    dueAtUtc: '2026-10-06T06:30:00.000Z', localTr: '06 Eki Sal 09:30',
    format: 'pdf',
    mediaTitle: `Cloud misconfigurations that actually get exploited`,
    text: `Attackers rarely "hack" cloud. They log in.

Most cloud incidents do not start with a novel exploit. They start with a setting someone left open, a key someone committed, or a role that could do far more than the job required.

The carousel below is the short list of cloud misconfigurations we see turn into real incidents — the ones worth checking this week, not the 200-item benchmark you will never finish.

None of this needs a new tool. It needs someone to look at what you already run with an attacker's incentives in mind.

${SOFT}

#CloudSecurity #CISO #CyberSecurity #AWS #Azure #InfoSec #AttackSurface`,
    slides: [
      { variant: 'cover', kicker: `Cloud security`, title: `Cloud misconfigurations that actually get exploited`, body: `Eight settings that turn into incidents — and how to check them fast.` },
      { variant: 'content', kicker: `Reality`, title: `Attackers log in, they do not break in`, body: `The common cloud breach path is a valid credential plus an over-permissioned role. No zero-day required. That is good news: these are findable before someone else finds them.` },
      { variant: 'content', kicker: `01`, title: `Public storage that should not be`, bullets: [`Object stores exposed to the internet "temporarily"`, `Snapshots and backups with public read`, `Check: list every bucket, prove each public one is meant to be`] },
      { variant: 'content', kicker: `02`, title: `Identities that can do too much`, bullets: [`Roles with wildcard permissions "to unblock a deploy"`, `Human users with standing admin instead of just-in-time`, `Check: who can delete logs, create keys, or assume any role?`] },
      { variant: 'content', kicker: `03`, title: `Keys living where they should not`, bullets: [`Long-lived access keys in code, CI variables, images`, `No rotation, no expiry`, `Check: can any key be traced to an owner and a rotation date?`] },
      { variant: 'content', kicker: `04`, title: `Networks open by default`, bullets: [`Management ports reachable from 0.0.0.0/0`, `Databases with a public endpoint "for the migration"`, `Check: what is internet-facing that does not need to be?`] },
      { variant: 'content', kicker: `05`, title: `Logging that is not actually on`, bullets: [`Audit trails disabled in the accounts that matter most`, `Logs writable (and therefore deletable) by the same role being audited`, `Check: could an intruder erase their own tracks?`] },
      { variant: 'content', kicker: `The pattern`, title: `Exposure, identity, secrets, network, logging`, body: `Almost every cloud incident maps to one of these five. Walk each account against them once and you have closed the paths that get used, not the ones that look impressive in a report.` },
      { variant: 'cta', title: `Check the exploitable, not the theoretical`, body: `Pick your two most important accounts and run this list against them first. Confirmed-exploitable beats a 200-item benchmark nobody finishes.` },
    ],
  },
  {
    id: 'p16-shadow-it',
    dueAtUtc: '2026-10-07T07:30:00.000Z', localTr: '07 Eki Car 10:30',
    format: 'image',
    mediaTitle: `The apps you don't manage are still your risk`,
    text: `Every company has a second IT estate nobody signed off on.

A team needed a tool on Tuesday, expensed it, connected it to your Google or Microsoft tenant with a broad OAuth scope, and moved on. It now holds company data — and you have no inventory entry, no owner, and no offboarding plan for it.

Shadow SaaS is not a policy failure. It is a speed-of-business reality. The job is not to ban it; it is to see it.

Three places to look first:
- OAuth grants in your identity provider (what has access to mail, files, calendars?)
- Expense reports for recurring software charges under $50
- DNS and SSO logs for apps you have never heard of

You cannot protect what you cannot list. Start with the inventory, not the crackdown.

${SOFT}

#ShadowIT #SaaS #CISO #CyberSecurity #IdentitySecurity #InfoSec #RiskManagement`,
    slides: [{ variant: 'cover', kicker: `Shadow IT`, title: `The apps you don't manage are still your risk`, bullets: [`OAuth grants with broad scopes into your tenant`, `SaaS bought on expense, connected in minutes`, `No owner, no inventory, no offboarding`, `Start by seeing it — not by banning it`] }],
  },
  {
    id: 'p17-assumed-breach',
    dueAtUtc: '2026-10-08T11:30:00.000Z', localTr: '08 Eki Per 14:30',
    format: 'text',
    mediaTitle: '',
    text: `"Are we secure?" is the wrong question.

It invites a yes, and yes is never true. The more useful question a board can ask is: "Assume someone is already inside. How far do they get, and how fast do we notice?"

That single reframe changes what you test.

You stop grading the front door and start measuring what happens after it opens:
- From one compromised laptop, can an attacker reach the customer database?
- How many steps, and does any of them trip an alert?
- If nothing alerts, how long until a human notices on their own?
- When they do, is there a runbook — or a group chat and a bad afternoon?

An "assumed breach" exercise is uncomfortable because it usually works. But the discomfort is the point: it surfaces the paths and blind spots that a perimeter scan will always miss, while there is still time to fix them cheaply.

Prevention keeps people out. Assumed-breach testing tells you what your prevention is actually worth on the day it fails.

If you have never run one, that is the gap worth closing before the next audit — not another tool.

#CISO #RedTeam #CyberSecurity #InfoSec #ThreatDetection #SecurityLeadership #RiskManagement`,
  },
  // ─────────────────────────────── HAFTA 6 ───────────────────────────────
  {
    id: 'p18-secrets-in-code',
    dueAtUtc: '2026-10-13T06:30:00.000Z', localTr: '13 Eki Sal 09:30',
    format: 'pdf',
    mediaTitle: `How credentials leak through your own code`,
    text: `The fastest way into a company is often a key it published itself.

A developer hardcodes a token to test something, commits it, and it works — so it stays. Months later that repo is public, or a laptop is stolen, or a contractor's account is phished, and the key is still valid.

Secret leakage is quiet, common, and entirely preventable. The carousel below covers where secrets hide, why rotation matters more than detection, and the three controls that stop most of it.

The uncomfortable part: scanning for secrets tells you what already leaked. The fix is making sure a leaked secret is worthless by the time anyone finds it.

${SOFT}

#AppSec #DevSecOps #CISO #CyberSecurity #SecretsManagement #InfoSec #CloudSecurity`,
    slides: [
      { variant: 'cover', kicker: `App security`, title: `How credentials leak through your own code`, body: `Where secrets hide, why rotation beats detection, and three controls that stop most of it.` },
      { variant: 'content', kicker: `The pattern`, title: `Convenience becomes exposure`, body: `A token is hardcoded "just to test," it works, and it never leaves. The risk is not the moment it is written — it is the months it stays valid and reachable.` },
      { variant: 'content', kicker: `Where they hide`, title: `Not just source code`, bullets: [`Git history — deleted from the file, alive in the log`, `CI/CD variables and build logs`, `Container images and their layers`, `Config files shipped to the client side`] },
      { variant: 'content', kicker: `The hard truth`, title: `Detection is a lagging control`, body: `A secret scanner finds what has already leaked. Useful — but it is cleanup. The real win is making a leaked secret expire before it is exploited.` },
      { variant: 'content', kicker: `Control 1`, title: `Short-lived, not standing`, bullets: [`Prefer tokens that expire in minutes/hours`, `Just-in-time issuance over long-lived keys`, `A leaked 15-minute token is a non-event`] },
      { variant: 'content', kicker: `Control 2`, title: `A vault, not the repo`, bullets: [`Secrets injected at runtime from a manager`, `Nothing sensitive committed, ever`, `Access to the vault is itself logged and scoped`] },
      { variant: 'content', kicker: `Control 3`, title: `Rotate on a schedule and on exit`, bullets: [`Automatic rotation so age is bounded`, `Immediate rotation when someone offboards`, `Know, for any key, its owner and last rotation`] },
      { variant: 'cta', title: `Make leaked secrets worthless`, body: `You will never stop every accidental commit. You can make sure that by the time a secret is found, it no longer opens anything.` },
    ],
  },
  {
    id: 'p19-asm',
    dueAtUtc: '2026-10-14T07:30:00.000Z', localTr: '14 Eki Car 10:30',
    format: 'pdf',
    mediaTitle: `Know your attack surface before someone maps it for you`,
    text: `An attacker's first step is free reconnaissance. Yours should be too.

Before anyone tries a payload, they build a map: your domains, subdomains, exposed services, cloud ranges, forgotten hosts, and the technology behind each. Most organisations have never built that same map for themselves — so the attacker knows the estate better than the defender does.

The carousel below is how to run attack surface discovery the way the other side does it, and what to do with what you find.

The goal is not a longer asset list. It is closing the gap between "assets we manage" and "assets that answer when the internet knocks."

${SOFT}

#AttackSurface #ASM #CISO #CyberSecurity #ThreatIntel #InfoSec #ExternalRisk`,
    slides: [
      { variant: 'cover', kicker: `External exposure`, title: `Know your attack surface before someone maps it for you`, body: `Recon the way the other side does it — then close the gap.` },
      { variant: 'content', kicker: `The gap`, title: `Managed assets vs answering assets`, body: `Your CMDB lists what you decided to run. The internet lists what actually responds. The dangerous items live in the difference — and only the attacker is looking there.` },
      { variant: 'content', kicker: `Step 1`, title: `Enumerate, do not assume`, bullets: [`All domains and subdomains, including marketing and legacy`, `Cloud IP ranges across every account and region`, `Third-party services on your domain (status pages, portals)`] },
      { variant: 'content', kicker: `Step 2`, title: `Fingerprint what answers`, bullets: [`Which ports and services are open to the world?`, `What software and versions are exposed in banners?`, `Which login pages, APIs, and admin panels are reachable?`] },
      { variant: 'content', kicker: `Step 3`, title: `Hunt the forgotten`, bullets: [`Staging and dev that never came down`, `Dangling DNS to deleted cloud resources`, `Old apps still up long after their replacement shipped`] },
      { variant: 'content', kicker: `Step 4`, title: `Prioritise by reachability, not severity alone`, body: `A medium-severity flaw on an internet-facing forgotten host beats a critical on a well-defended internal one. Fix what an outsider can actually touch first.` },
      { variant: 'content', kicker: `Cadence`, title: `Once is a snapshot; the surface moves`, body: `New subdomains, new cloud, new vendors appear weekly. Discovery is a habit, not a project — otherwise your map is stale the day after you finish it.` },
      { variant: 'cta', title: `Map yourself first`, body: `The organisations that get surprised are the ones who never looked from the outside. Build the map, then keep it current.` },
    ],
  },
  {
    id: 'p20-vendor-offboarding',
    dueAtUtc: '2026-10-15T11:30:00.000Z', localTr: '15 Eki Per 14:30',
    format: 'image',
    mediaTitle: `The vendor left. Their access didn't.`,
    text: `Contracts end. Access rarely does.

A vendor finished the project in March. It is now October. Their integration token still works, their VPN account is still enabled, and the shared login they used is still valid — because offboarding a vendor is nobody's clear job.

Third-party access that outlives the relationship is one of the most common and least-watched paths into an organisation. It does not show up in a vulnerability scan because nothing is "vulnerable" — the access is simply still there.

A five-minute quarterly question fixes most of it:
- Which external parties have any access right now?
- Which of those relationships have actually ended?
- Who owns turning each one off, and by when?

You do not need a tool for this. You need a list and an owner.

${SOFT}

#ThirdPartyRisk #CISO #CyberSecurity #VendorRisk #IdentitySecurity #InfoSec #AccessControl`,
    slides: [{ variant: 'cover', kicker: `Third-party risk`, title: `The vendor left. Their access didn't.`, bullets: [`Integration tokens still valid months later`, `VPN and shared logins never disabled`, `No owner for vendor offboarding`, `Quarterly: who has access, and should they?`] }],
  },
  // ─────────────────────────────── HAFTA 7 ───────────────────────────────
  {
    id: 'p21-phishing-resistant-mfa',
    dueAtUtc: '2026-10-20T06:30:00.000Z', localTr: '20 Eki Sal 09:30',
    format: 'pdf',
    mediaTitle: `Not all MFA survives a real phishing attack`,
    text: `You rolled out MFA. Attackers adapted. Here is what still holds.

The message "we have MFA" is doing a lot of quiet work. SMS codes, push approvals, and one-time passwords all raise the bar — and all can be defeated by a determined phishing kit that relays your code in real time or fatigues you into tapping "approve."

The carousel below ranks MFA methods by how they behave under a real attack, not on a compliance checklist, and shows the practical path to phishing-resistant sign-in without a year-long project.

The point is not to scare anyone off MFA. It is to be honest that not all MFA is equal when someone is actively trying.

${SOFT}

#IdentitySecurity #MFA #CISO #CyberSecurity #ZeroTrust #Phishing #InfoSec`,
    slides: [
      { variant: 'cover', kicker: `Identity`, title: `Not all MFA survives a real phishing attack`, body: `Ranking methods by how they behave under attack — and the path to phishing-resistant sign-in.` },
      { variant: 'content', kicker: `The gap`, title: `"We have MFA" is not one thing`, body: `MFA is a category, not a control. The method decides whether a modern phishing kit walks straight through it or hits a wall.` },
      { variant: 'content', kicker: `Weakest`, title: `SMS and email codes`, bullets: [`Relayed in real time by a proxy phishing page`, `SIM-swap and mailbox compromise bypass them`, `Better than nothing — but assume they can be defeated`] },
      { variant: 'content', kicker: `Middle`, title: `Authenticator codes and push`, bullets: [`OTP codes still relayable through a fake login`, `Push fatigue: enough prompts, someone taps approve`, `Number-matching helps, but the channel is still phishable`] },
      { variant: 'content', kicker: `Strongest`, title: `Phishing-resistant by design`, bullets: [`FIDO2 / passkeys / hardware security keys`, `Bound to the real domain — a fake site gets nothing`, `Nothing to type, relay, or approve by mistake`] },
      { variant: 'content', kicker: `Practical path`, title: `You do not need a big-bang rollout`, bullets: [`Start with admins and high-value accounts`, `Make phishing-resistant the default for new joiners`, `Keep weaker methods only as a temporary fallback`] },
      { variant: 'content', kicker: `Also`, title: `Protect the recovery path`, body: `Attackers skip the strong door and knock on the weak one. If account recovery falls back to SMS or a help-desk call with lax checks, your strongest MFA does not matter.` },
      { variant: 'cta', title: `Grade your MFA by attack, not audit`, body: `List where each method is in use, starting with your admins. If the answer for privileged accounts is SMS or push, that is the first thing to move.` },
    ],
  },
  {
    id: 'p22-tabletop',
    dueAtUtc: '2026-10-21T07:30:00.000Z', localTr: '21 Eki Car 10:30',
    format: 'pdf',
    mediaTitle: `A 60-minute tabletop that finds real gaps`,
    text: `Most incident plans are tested for the first time during the incident.

That is the worst possible moment to discover the on-call rota is out of date, nobody can approve isolating a server, or legal was never in the loop. A tabletop exercise finds those gaps in a conference room instead of a crisis — and it takes an hour, not a consultant's month.

The carousel below is a ready-to-run 60-minute tabletop: the scenario, the questions that expose real gaps, and how to capture actions without it turning into theatre.

Run it once and you will leave with a short list of fixes that are cheaper today than they will ever be again.

${SOFT}

#IncidentResponse #CISO #CyberSecurity #Resilience #Ransomware #InfoSec #SecurityLeadership`,
    slides: [
      { variant: 'cover', kicker: `Incident response`, title: `A 60-minute tabletop that finds real gaps`, body: `Scenario, questions, and outputs — run it in a room, not a crisis.` },
      { variant: 'content', kicker: `Why`, title: `Plans fail on the details`, body: `The strategy is usually fine. It breaks on who can decide, who to call, and where the runbook lives. A tabletop pressure-tests exactly those.` },
      { variant: 'content', kicker: `Setup`, title: `Keep it small and real`, bullets: [`60 minutes, one room, phones down`, `The people who would really respond — not deputies`, `A facilitator who injects, not a slide deck`] },
      { variant: 'content', kicker: `Scenario`, title: `Ransomware, 09:00 Monday`, body: `Finance reports files encrypting on a shared drive. A note demands payment. You have partial visibility. Now walk it forward — decision by decision, out loud.` },
      { variant: 'content', kicker: `Questions that bite`, title: `Where it usually breaks`, bullets: [`Who authorises taking systems offline — and are they reachable now?`, `How do we communicate if email/Teams is down?`, `When do legal, comms, and leadership get pulled in?`, `What is our answer to the media before we have facts?`] },
      { variant: 'content', kicker: `The test`, title: `Prove the backups`, body: `Ask the hardest question last: can we restore, and have we ever actually tried? "We have backups" and "we have restored from backups" are different sentences.` },
      { variant: 'content', kicker: `Output`, title: `Leave with actions, not vibes`, bullets: [`Every gap becomes an owner + a date`, `Update the runbook the same week`, `Re-run in 6 months against a different scenario`] },
      { variant: 'cta', title: `Find the gaps in a room`, body: `An hour of structured discomfort now is worth more than any document. Pick a date, pick a scenario, and run it.` },
    ],
  },
  {
    id: 'p23-api-security',
    dueAtUtc: '2026-10-22T11:30:00.000Z', localTr: '22 Eki Per 14:30',
    format: 'pdf',
    mediaTitle: `API security in plain terms`,
    text: `Your APIs are the front door now — and they are often the least tested one.

Traffic moved from web pages to APIs, but testing did not always follow. The result is a common gap: strong network security, hardened web apps, and an API layer that trusts the caller far more than it should.

The carousel below translates the most common API weaknesses into plain language — what they are, why they happen, and the check that catches each — without drowning you in jargon.

Most of these are logic problems, not exotic exploits. That is why scanners miss them and why a human who asks "what if I change this ID?" finds them.

${SOFT}

#APIsecurity #AppSec #CISO #CyberSecurity #OWASP #InfoSec #DevSecOps`,
    slides: [
      { variant: 'cover', kicker: `App security`, title: `API security in plain terms`, body: `The common weaknesses, why they happen, and the check that catches each.` },
      { variant: 'content', kicker: `Why now`, title: `The front door moved`, body: `Business logic lives behind APIs today. Many were built for speed and assume the client is honest — which an attacker never is.` },
      { variant: 'content', kicker: `01`, title: `Object-level access (BOLA)`, bullets: [`Change the ID in the request, get someone else's data`, `The API checks you are logged in, not that it is your record`, `Check: can user A read user B's object by guessing an ID?`] },
      { variant: 'content', kicker: `02`, title: `Function-level access`, bullets: [`Admin endpoints reachable by normal users`, `"Hidden" routes that are only hidden in the UI`, `Check: does the server enforce role, or trust the front end?`] },
      { variant: 'content', kicker: `03`, title: `Too much data returned`, bullets: [`Endpoints ship full records, UI shows a slice`, `Sensitive fields leak in the raw response`, `Check: read the JSON, not the screen`] },
      { variant: 'content', kicker: `04`, title: `No limits, no throttling`, bullets: [`Brute-force and scraping run unchecked`, `Expensive queries with no rate limit = easy DoS`, `Check: what stops 10,000 requests a minute?`] },
      { variant: 'content', kicker: `The theme`, title: `These are logic flaws`, body: `Most API risk is not a memory-corruption exploit. It is trust the server should not have extended. That is why "what if I change this?" testing beats a signature scanner here.` },
      { variant: 'cta', title: `Test the API like an attacker`, body: `Pick your most sensitive endpoint and try to read a record that is not yours. If it works, you have found the highest-value fix on the roadmap.` },
    ],
  },
  // ─────────────────────────────── HAFTA 8 ───────────────────────────────
  {
    id: 'p24-leading-metrics',
    dueAtUtc: '2026-10-27T06:30:00.000Z', localTr: '27 Eki Sal 09:30',
    format: 'pdf',
    mediaTitle: `Security metrics that predict incidents`,
    text: `Most security dashboards tell you what already happened. The useful ones tell you what is about to.

Lagging metrics — incidents this quarter, tickets closed — are easy to collect and comfortable to report. They also arrive too late to change anything. Leading metrics are harder to gather and far more valuable: they move before an incident, so you can act while it is still cheap.

The carousel below contrasts the two and gives a short set of leading indicators worth tracking, whatever tools you run.

If your reporting is entirely rear-view, you are managing yesterday. The point of a metric is to change a decision you still have time to make.

${SOFT}

#SecurityMetrics #CISO #CyberSecurity #RiskManagement #BoardReporting #InfoSec #SecurityLeadership`,
    slides: [
      { variant: 'cover', kicker: `Measurement`, title: `Security metrics that predict incidents`, body: `Leading vs lagging — and the indicators that move before things break.` },
      { variant: 'content', kicker: `The trap`, title: `Comfortable, but too late`, body: `"Incidents this quarter" is easy to chart and impossible to act on — it is history. A metric earns its place only if it can change a decision you still have time to make.` },
      { variant: 'content', kicker: `Lagging`, title: `Rear-view (keep, but do not lead with)`, bullets: [`Incidents and breaches after the fact`, `Tickets closed / tools deployed`, `Audit findings from last cycle`] },
      { variant: 'content', kicker: `Leading 1`, title: `Time to remediate criticals`, body: `Not how many criticals — how fast the confirmed ones close. A rising number is an early warning long before it becomes an incident.` },
      { variant: 'content', kicker: `Leading 2`, title: `Attack surface drift`, body: `New internet-facing assets appearing between reviews. Growth you did not plan is exposure you have not assessed.` },
      { variant: 'content', kicker: `Leading 3`, title: `Coverage of the crown jewels`, bullets: [`Are your most critical systems actually monitored?`, `When did each last get tested, not just scanned?`, `Standing privileged access still outstanding`] },
      { variant: 'content', kicker: `Leading 4`, title: `Detection proven, not assumed`, body: `From your last exercise: did the alerts fire, and how fast did a human respond? A control you have never triggered is a hope, not a metric.` },
      { variant: 'cta', title: `Report the future, not the past`, body: `Keep two or three leading indicators and show the same ones every quarter. Direction beats decimals — and it arrives in time to matter.` },
    ],
  },
  {
    id: 'p25-zero-trust',
    dueAtUtc: '2026-10-28T07:30:00.000Z', localTr: '28 Eki Car 10:30',
    format: 'image',
    mediaTitle: `Zero trust, minus the marketing`,
    text: `"Zero trust" has been sold as a product for so long that the actual idea got buried.

It is not a box you buy. It is a principle: stop trusting something just because it is inside the network. Verify every request on its merits — who, what device, what resource — every time.

Stripped of the vendor gloss, the practical starting moves are unglamorous and effective:
- Strong identity on every access, internal included (see: phishing-resistant MFA)
- Least privilege by default — access to the job, not the building
- Segment the network so one compromised host does not reach everything
- Verify device health, not just user credentials
- Log and review access as if an insider might misuse it

You do not "finish" zero trust, and you do not need a platform to start. You need to pick the highest-trust assumption you currently make and remove it.

${SOFT}

#ZeroTrust #CISO #CyberSecurity #IdentitySecurity #NetworkSecurity #InfoSec #SecurityArchitecture`,
    slides: [{ variant: 'cover', kicker: `Architecture`, title: `Zero trust, minus the marketing`, bullets: [`Not a product — a principle: verify every request`, `Least privilege: access to the job, not the building`, `Segment so one host can't reach everything`, `Start by removing your biggest trust assumption`] }],
  },
  {
    id: 'p26-ransomware-72h',
    dueAtUtc: '2026-10-29T11:30:00.000Z', localTr: '29 Eki Per 14:30',
    format: 'pdf',
    mediaTitle: `The first 72 hours of a ransomware incident`,
    text: `When ransomware hits, the plan you improvise is the plan you get.

The technical response matters, but the first three days are won or lost on decisions: what to isolate, who to tell, whether to pay, and how to keep the business partly running. Organisations that handle it well are not luckier — they decided most of this in advance.

The carousel below is a plain timeline of the first 72 hours: what to do, in what order, and the decisions to make before, not during.

You do not need to have lived through one to prepare for it. You need to have argued about these choices once, calmly, while nothing was on fire.

${SOFT}

#Ransomware #IncidentResponse #CISO #CyberSecurity #Resilience #InfoSec #BusinessContinuity`,
    slides: [
      { variant: 'cover', kicker: `Incident response`, title: `The first 72 hours of a ransomware incident`, body: `A plain timeline — and the decisions to make before, not during.` },
      { variant: 'content', kicker: `Hour 0–1`, title: `Contain, do not panic-pull`, bullets: [`Isolate affected systems from the network`, `Preserve evidence — do not wipe or reboot blindly`, `Start a written timeline; you will need it later`] },
      { variant: 'content', kicker: `Hour 1–4`, title: `Convene and assess`, bullets: [`Stand up the response team and a single decision-maker`, `Scope it: what is hit, what is spreading, what is safe?`, `Open the legal/comms line early, not on day three`] },
      { variant: 'content', kicker: `Hour 4–24`, title: `Decide on the hard questions`, body: `Do backups exist and restore cleanly? What is the regulatory clock (many regimes require notice within days)? Is data exfiltration in play, not just encryption? These answers shape everything after.` },
      { variant: 'content', kicker: `The payment question`, title: `Decide the stance in advance`, body: `Paying funds the next attack, may breach sanctions, and does not guarantee clean recovery. Whatever your position, having it written down beforehand keeps a bad day from becoming a rushed decision.` },
      { variant: 'content', kicker: `Day 1–3`, title: `Recover in priority order`, bullets: [`Restore the business-critical few first, cleanly`, `Rebuild rather than trust compromised hosts`, `Rotate every credential the attacker could have touched`] },
      { variant: 'content', kicker: `After`, title: `Close the door you came in through`, body: `Recovery is not "back to normal" — it is "back, without the original entry point." Find how they got in and fix it, or you are rehearsing for the sequel.` },
      { variant: 'cta', title: `Decide before, not during`, body: `Read this as a checklist, then argue through the hard calls with your team once. That single conversation is the cheapest insurance you will buy this year.` },
    ],
  },
  // ─────────────────────────────── HAFTA 9 ───────────────────────────────
  {
    id: 'p27-budget-cfo',
    dueAtUtc: '2026-11-03T06:30:00.000Z', localTr: '03 Kas Sal 09:30',
    format: 'pdf',
    mediaTitle: `How to justify a security budget to a CFO`,
    text: `"We need more budget for security" is the weakest sentence in the room.

CFOs do not fund fear, and they have heard "or we could get breached" too many times to move on it. They fund decisions with a cost, a benefit, and a number they can defend upward.

The carousel below reframes the security budget conversation in a CFO's language: risk in financial terms, spend tied to specific exposure, and the difference between insurance and theatre.

Value first, fear never. The goal is not to alarm the board into spending — it is to make the trade-off so clear that not spending looks like the risky choice.

${SOFT}

#CISO #SecurityLeadership #CyberSecurity #RiskManagement #BoardReporting #InfoSec #Budget`,
    slides: [
      { variant: 'cover', kicker: `Leadership`, title: `How to justify a security budget to a CFO`, body: `Risk in financial terms, spend tied to exposure, insurance vs theatre.` },
      { variant: 'content', kicker: `The problem`, title: `Fear is not a business case`, body: `"We might get breached" is unfalsifiable and easy to defer. A CFO funds a decision with a cost, a benefit, and a defensible number — give them that.` },
      { variant: 'content', kicker: `Move 1`, title: `Translate risk into money`, bullets: [`Which scenarios could stop revenue, and for how long?`, `Estimate impact in ranges, not false precision`, `"€X of revenue exposed for Y days" beats "critical risk"`] },
      { variant: 'content', kicker: `Move 2`, title: `Tie every ask to an exposure`, body: `Do not request "more security." Request the specific control that closes a specific, named gap — with the cost of leaving it open next to it.` },
      { variant: 'content', kicker: `Move 3`, title: `Separate insurance from theatre`, bullets: [`Insurance: measurably reduces a real, likely loss`, `Theatre: looks good in a slide, changes no outcome`, `Cut your own theatre before they cut your budget`] },
      { variant: 'content', kicker: `Move 4`, title: `Show what the last spend bought`, body: `Nothing earns the next euro like proving the last one worked. Bring one or two before/after numbers — time-to-remediate down, exposed assets closed.` },
      { variant: 'content', kicker: `Frame`, title: `Make not-spending the risk`, body: `You are not asking for money. You are presenting a priced choice and recommending one option. Done well, the expensive-looking path is obviously the cheaper one.` },
      { variant: 'cta', title: `Speak in trade-offs, not threats`, body: `Rebuild your top three asks as "gap, cost to close, cost to ignore." The conversation changes the moment the numbers do the arguing.` },
    ],
  },
  {
    id: 'p28-credential-hygiene',
    dueAtUtc: '2026-11-04T07:30:00.000Z', localTr: '04 Kas Car 10:30',
    format: 'image',
    mediaTitle: `Password advice you were given is mostly wrong now`,
    text: `Forced 90-day password changes. Mandatory symbols. A new rule every quarter. Most of it is outdated — and some of it makes you less safe.

Modern guidance (NIST 800-63B) is simpler and stronger, and it takes pressure off your users instead of adding it:
- Length beats complexity. A long passphrase outguns "P@ss1!" every time.
- Stop forcing periodic resets. They push people toward weak, predictable patterns. Reset on evidence of compromise, not the calendar.
- Screen new passwords against known-breached lists. This blocks the credentials attackers actually try.
- Make phishing-resistant MFA the real defence — the password stops being the single point of failure.

The uncomfortable part: the biggest credential risk is not weak passwords, it is reused ones. A password leaked from some unrelated site is tried against your login within hours. Breach-screening and MFA are what stop that, not another complexity rule.

Fewer arbitrary rules, better outcomes. That is the rare security trade with no downside.

${SOFT}

#IdentitySecurity #CISO #CyberSecurity #NIST #InfoSec #PasswordSecurity #MFA`,
    slides: [{ variant: 'cover', kicker: `Identity`, title: `Password advice you were given is mostly wrong now`, bullets: [`Length beats complexity — passphrases win`, `Stop calendar-based resets; reset on compromise`, `Screen against breached-password lists`, `The real risk is reuse — MFA + screening stop it`] }],
  },
  {
    id: 'p29-next-log4shell',
    dueAtUtc: '2026-11-05T11:30:00.000Z', localTr: '05 Kas Per 14:30',
    format: 'pdf',
    mediaTitle: `Be ready for the next internet-wide vulnerability`,
    text: `There will be another Log4Shell. The question is how fast you can answer three questions when it lands.

When a critical, widely-used component blows up overnight, the winners are not the ones with the best tools — they are the ones who can quickly say: do we use it, where, and how exposed are we? Most organisations spend the first 48 hours just trying to find out.

The carousel below is how to prepare now so the next internet-wide bug is a busy afternoon, not a lost week.

You cannot predict the vulnerability. You can absolutely prepare the answers to the questions it will force.

${SOFT}

#VulnerabilityManagement #CISO #CyberSecurity #IncidentResponse #SupplyChain #InfoSec #ThreatIntel`,
    slides: [
      { variant: 'cover', kicker: `Readiness`, title: `Be ready for the next internet-wide vulnerability`, body: `Prepare the three answers now, so the next one is an afternoon, not a week.` },
      { variant: 'content', kicker: `The pattern`, title: `Speed decides the damage`, body: `A critical flaw in a common component becomes a global race between attackers scanning for it and defenders finding it in their own estate. Preparation is what puts you ahead of the scan.` },
      { variant: 'content', kicker: `Question 1`, title: `Do we even use it?`, bullets: [`A current inventory of software and key dependencies`, `Including what your vendors embed (supply chain)`, `If answering takes days, that is the gap to fix now`] },
      { variant: 'content', kicker: `Question 2`, title: `Where, exactly?`, bullets: [`Which systems, which versions, internet-facing or not`, `Owners for each so patching is not a manhunt`, `A software bill of materials turns days into minutes`] },
      { variant: 'content', kicker: `Question 3`, title: `How exposed, right now?`, body: `Reachability first: an affected component behind ten controls is not the same emergency as one on your public edge. Triage by what an outsider can actually touch.` },
      { variant: 'content', kicker: `Have ready`, title: `The pieces that save the week`, bullets: [`A dependency inventory you can query fast`, `An emergency patch path that skips the six-week cycle`, `A comms template for customers and leadership`] },
      { variant: 'content', kicker: `Interim`, title: `Buy time when you cannot patch`, body: `Virtual patching, WAF rules, or taking a non-critical service offline are legitimate first moves. The goal on day one is to shrink exposure while the real fix is staged.` },
      { variant: 'cta', title: `Prepare the answers, not the panic`, body: `Run a dry-run with a made-up component this quarter. If you can answer "do we, where, how exposed" in an hour, you are ready for the real one.` },
    ],
  },
  // ─────────────────────────────── HAFTA 10 ──────────────────────────────
  {
    id: 'p30-risk-appetite',
    dueAtUtc: '2026-11-10T06:30:00.000Z', localTr: '10 Kas Sal 09:30',
    format: 'text',
    mediaTitle: '',
    text: `"How much cyber risk are we willing to accept?" — most boards have never actually answered this.

And because they have not, security teams are left guessing. Every decision becomes a negotiation with no agreed line: is this residual risk fine, or a problem? Do we spend, or accept? Without a stated appetite, the honest answer is "nobody knows," and the loudest voice wins.

Defining risk appetite does not require a framework consultant. It requires the board to answer a few plain questions and write the answers down:

- Which outcomes are simply unacceptable, at any cost? (Name them — customer data at scale, safety, insolvency-level loss.)
- Where are we willing to trade some risk for speed or cost, and how much?
- What level of disruption could we absorb and still recover — an hour, a day, a week?
- Who is allowed to accept a risk on the organisation's behalf, and up to what threshold?

The value is not the document. It is that, once these lines exist, hundreds of downstream decisions get faster and more consistent — because there is finally a standard to measure against instead of a monthly argument.

If your team cannot point to a stated risk appetite today, that conversation is worth more than any tool you could buy this quarter. It is also free.

#CISO #RiskManagement #BoardReporting #CyberSecurity #Governance #SecurityLeadership #InfoSec`,
  },
];
