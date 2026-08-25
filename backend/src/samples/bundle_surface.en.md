## EXECUTIVE SUMMARY

- **Overall risk level: High** — 5 areas were examined; the highest risk is in the **SSL/TLS Configuration Audit** area (an issue requiring urgent attention was detected at the certificate and/or protocol level.).
- ⚠️ **HTTPS is not supported:** The target did not respond over HTTPS (443); communication is carried in plaintext. The scan was run over http://. This is a serious finding in itself (below).
- **SSL/TLS Configuration Audit:** High — an issue requiring urgent attention was detected at the certificate and/or protocol level.
- **Security Headers & Information Leakage:** High — an externally accessible sensitive file was detected.
- **DNS & Email Security:** Medium — there are gaps to be addressed in email authentication.
- **CORS & Cookie Security:** Low — no notable CORS/cookie issue stood out.
- **CSP (Content Security Policy) Analysis:** Medium — CSP is missing/not enforced.
- **Recommended first step:** Start with the highest-risk area; for each finding, ready-made step-by-step commands are provided in the "AI Fix Suggestions" section.

## OVERALL ASSESSMENT

**Risk Level: High**

This target does not respond over HTTPS; communication is carried in plaintext — the priority is to move to HTTPS with a valid TLS certificate. The other areas were examined over http://. The highest risk was detected in the **SSL/TLS Configuration Audit** area (an issue requiring urgent attention was detected at the certificate and/or protocol level.); priority remediation is recommended. Each area is reported separately below.

## IDENTIFIED RISKS

| Finding | Severity | Description |
|-------|--------|----------|
| HTTPS is not supported (unencrypted communication) | High | The site does not respond over HTTPS; all traffic is carried in plaintext — it can be intercepted/modified and sessions/passwords stolen. Fix: valid TLS certificate + HTTP→HTTPS redirect + HSTS. |

## SSL/TLS Configuration Audit

### TLS CERTIFICATE STATUS

⚠️ This target **did not respond over HTTPS (443)**; no valid TLS certificate was found. The site is served only over **unencrypted HTTP**.

### TLS PROTOCOL & CIPHER

- **Active protocol:** not detectable
- **Cipher:** not detectable
- **Legacy/weak version support:** Not observed (only TLS 1.2+ seen)

### HSTS (HTTP Strict Transport Security)

- **Status:** Absent — The browser is not instructed to enforce HTTPS; there is a risk of SSL-stripping/downgrade attacks on initial requests.

### IDENTIFIED RISKS

| Finding | Severity | Description |
|-------|--------|----------|
| HTTPS not supported (unencrypted communication) | High | The site does not respond over HTTPS; all traffic is carried in the clear (plaintext). An attacker on the same network can eavesdrop, steal sessions/passwords or alter content. Fix: valid TLS certificate + HTTP→HTTPS redirect + HSTS. |
| HSTS missing | Medium | HTTPS enforcement is not signalled to the browser; open to downgrade attacks. |

## Security Headers & Information Leakage

### HTTP SECURITY HEADERS

| Header | Status | Description |
|--------|-------|----------|
| Strict-Transport-Security | Absent | HTTPS enforcement is not signalled; SSL-stripping risk. |
| Content-Security-Policy | Absent | No browser defence against XSS/injection. |
| X-Frame-Options | Absent | Open to clickjacking; can be embedded in an iframe. |
| X-Content-Type-Options | Absent | MIME-sniffing is possible. |
| Referrer-Policy | Absent | Referrer information may leak to external sources. |
| Permissions-Policy | Absent | Sensitive browser APIs are not restricted. |
| X-XSS-Protection | Absent | The legacy browser XSS filter is not set (not critical in modern browsers). |

### INFORMATION LEAKAGE / EXPOSED FILES

Common sensitive paths were checked with a single GET (content verified — HTTP 200 alone is not treated as evidence):

| Path | Status | Note |
|-----|-------|-----|
| `/.git/config` | Closed | HTTP 400 / empty body — not reachable |
| `/.env` | Closed | HTTP 404 / empty body — not reachable |
| `/.git/HEAD` | Closed | HTTP 400 / empty body — not reachable |
| `/backup.zip` | Closed | HTTP 404 / empty body — not reachable |
| `/.DS_Store` | Closed | HTTP 404 / empty body — not reachable |
| `/wp-config.php.bak` | Closed | HTTP 404 / empty body — not reachable |
| `/ftp` | Closed | HTTP 404 / empty body — not reachable |
| `/backup` | Closed | HTTP 404 / empty body — not reachable |
| `/backups` | Closed | HTTP 404 / empty body — not reachable |
| `/uploads` | Closed | HTTP 404 / empty body — not reachable |
| `/files` | Closed | HTTP 400 / empty body — not reachable |
| `/admin` | Closed | HTTP 404 / empty body — not reachable |
| `/.svn/entries` | Closed | HTTP 400 / empty body — not reachable |
| `/.htaccess` | Closed | HTTP 403 / empty body — not reachable |
| `/config.php.bak` | Closed | HTTP 404 / empty body — not reachable |
| `/db.sql` | ⚠️ EXPOSED | expected file format confirmed (not catch-all) |
| `/dump.sql` | Closed | HTTP 404 / empty body — not reachable |
| `/backup.tar.gz` | Closed | HTTP 404 / empty body — not reachable |
| `/backup.tar` | Closed | HTTP 404 / empty body — not reachable |
| `/www.zip` | Closed | HTTP 404 / empty body — not reachable |
| `/site.zip` | Closed | HTTP 404 / empty body — not reachable |
| `/backup.old` | Closed | HTTP 404 / empty body — not reachable |
| `/backup.backup` | Closed | HTTP 404 / empty body — not reachable |
| `/index.php.bak` | Closed | HTTP 404 / empty body — not reachable |
| `/index.php~` | Closed | HTTP 404 / empty body — not reachable |
| `/.env.bak` | Closed | HTTP 404 / empty body — not reachable |
| `/.env.old` | Closed | HTTP 404 / empty body — not reachable |
| `/database.sql` | Closed | HTTP 404 / empty body — not reachable |

### ADDITIONAL INFORMATION-LEAKAGE OBSERVATIONS

| Control | Result |
|-----|-------|
| Directory listing (autoindex / "Index of /") · CWE-548 | ✅ 6 directories tried, no listing |
| Verbose error / server-path disclosure · CWE-209 | ✅ No indicator found |
| Password-field autocomplete policy · CWE-522 | ✅ Appropriate / no password field observed |

> All GET-only/passive observation — content is NOT fetched/shown; a leaked path is REDACTED. "No indicator found" does NOT PROVE it is secure; it only shows that no indicator emerged from the passive methods attempted.

### IDENTIFIED RISKS

| Finding | Severity | Description |
|-------|--------|----------|
| Sensitive file accessible (`/db.sql`) | High | Content verified; risk of configuration/source-code leakage. Access must be blocked immediately. |
| Outdated / unsupported software version disclosed (PHP/7.1.26 — EOL) | High | The PHP 7.x series is officially end-of-life (security updates for 7.x ended in late 2022). Numerous known vulnerabilities remain unpatched. CWE-1104 · OWASP A06:2021 (Vulnerable & Outdated Components). Remediation: upgrade to a current, supported PHP version (8.2+) and hide the version signature (expose_php=Off). |
| Out-of-date software version disclosed (Apache/2.4.25 — very old patch level) | Medium | The Apache 2.4 series is supported, but Apache/2.4.25 is a very old patch level; intervening security patches appear not to have been applied. CWE-1104 · OWASP A06:2021 (Vulnerable & Outdated Components). Remediation: upgrade to the current patch of the 2.4 series and hide the version signature (ServerTokens Prod). |
| Critical security headers missing (Content-Security-Policy, X-Frame-Options) | Medium | Browser defence against XSS/clickjacking is weak. (missing on 2/2 pages) |
| Additional headers missing (Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection) | Medium | Defence in depth is weak. (missing on 2/2 pages) |

## DNS & Email Security

### SPF (Sender Policy) — checked domain: `vulnweb.com`

- **Status:** Present — `v=spf1 ~all`
- **Strictness:** `~all` — soft (softfail; acceptable, not ideal).

### DMARC (Authentication Policy) — checked domain: `vulnweb.com`

- **Status:** Absent — No DMARC record was found. No enforcement is applied based on SPF/DKIM results; protection against spoofing is weak.

### DKIM (Signature)

- **Status:** Not detected — No DKIM record was found at common selectors (default/google/selector1…). You may be using a different selector; this does not definitely mean "no record".

### DNSSEC

- **Status:** Passive/absent — DNS responses are not signed; more exposed to DNS spoofing/cache-poisoning risk.

### IDENTIFIED RISKS

| Finding | Severity | Description |
|-------|--------|----------|
| DMARC missing | Medium | SPF/DKIM results are not enforced. |
| DKIM not detected | Informational | Not found at common selectors (may be a different selector). |
| DNSSEC passive | Informational | DNS responses are not signed. |

## CORS & Cookie Security

### CORS CONFIGURATION (tested on 2/2 pages)

- **Test Origin:** `https://cybertestify-cors-probe.example` — a harmless Origin header was sent to each page and the response evaluated.
- **Most permissive observed policy** (`/`): Access-Control-Allow-Origin: not sent (closed — secure default); Allow-Credentials: not sent.

### COOKIE FLAGS (all cookies observed across 2 pages)

- No Set-Cookie was observed on any of the 2 scanned pages.

### IDENTIFIED RISKS

- No notable risk stood out in the CORS and cookie configuration.

## CSP (Content Security Policy) Analysis

### CSP STATUS

- **Status:** Absent — No Content-Security-Policy header is sent at all.

### CSP DIRECTIVE ANALYSIS

- As there is no enforced CSP, no directive analysis could be performed.

### IDENTIFIED RISKS

| Finding | Severity | Description |
|-------|--------|----------|
| CSP entirely missing | Medium | No browser-level defence against XSS and content injection. The CSP header is missing on ALL 2 of the scanned pages. |

## POSITIVE ASSURANCE — AREAS CHECKED

Including the areas with no finding, the external-surface checks were genuinely run across **2 unique pages** including the home page. The table below also shows the "no issue found" results transparently:

| Control area | Result |
|---------------|-------|
| SSL/TLS Configuration Audit | ⚠️ Finding present (High — detailed above) |
| Security Headers & Information Leakage | ⚠️ Finding present (High — detailed above) |
| DNS & Email Security | ⚠️ Finding present (Medium — detailed above) |
| CORS & Cookie Security | ✅ No issue found |
| CSP (Content Security Policy) Analysis | ⚠️ Finding present (Medium — detailed above) |

> **Three-state distinction (honesty):** ✅ *No issue found* = the check ran and came back clean · ⚠️ *Finding present* = detailed above · ⚠️ *Not assessable* = no data could be collected (does NOT mean secure).

### What this package DOES and DOES NOT check

**DOES (passive — only page retrieval via GET + harmless Origin/DNS query):** TLS/certificate, HTTP security headers, CORS policy, cookie flags (Secure/HttpOnly/SameSite), Content-Security-Policy, DNS/email records (SPF/DKIM/DMARC/DNSSEC), exposed sensitive files (incl. common backup patterns), directory listing (autoindex), verbose-error/server-path disclosure (redacted), password-field autocomplete policy, outdated/unsupported software versions — across the 2 discovered pages.

**DOES NOT:** Active vulnerability verification (payload/probe attempts such as SQLi/XSS/IDOR), authenticated flow testing, business-logic abuse. These are within the scope of the **Active Verification** and **Full-Scope Pentest** packages. This report relies on passive observation; "no finding" in an area **does NOT PROVE** it is secure, because no active exploit was attempted — it only shows that the externally observed configuration is clean.

