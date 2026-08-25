## EXECUTIVE SUMMARY

- **Overall risk level: High** — 5 areas were examined; the highest risk is in the **SSL/TLS Configuration Audit** area (an issue requiring urgent attention at the certificate and/or protocol level was detected.).
- ⚠️ **HTTPS not supported:** The target did not respond over HTTPS (443); communication is carried unencrypted (plaintext). The scan was performed over http://. This is a serious finding on its own (below).
- **SSL/TLS Configuration Audit:** High — an issue requiring urgent attention at the certificate and/or protocol level was detected.
- **Security Headers & Information Leakage:** High — an externally accessible sensitive file was detected.
- **DNS & Email Security:** Medium — there are gaps in e-mail authentication that need addressing.
- **CORS & Cookie Security:** Low — no notable CORS/cookie issue stood out.
- **CSP (Content Security Policy) Analysis:** Medium — CSP is missing/not enforced.
- **Recommended first step:** Start with the highest-risk area; ready-made step-by-step commands for each finding are in the "AI Solution Recommendations" section.

## OVERALL ASSESSMENT

**Risk Level: High**

This target does not respond over HTTPS; communication is carried unencrypted (plaintext) — migrating to HTTPS with a valid TLS certificate should be the priority. The other areas were examined over http://. The highest risk was detected in the **SSL/TLS Configuration Audit** area (an issue requiring urgent attention at the certificate and/or protocol level was detected.); priority remediation is recommended. Each area is reported separately below.

## IDENTIFIED RISKS

| Finding | Severity | Description |
|-------|--------|----------|
| HTTPS not supported (unencrypted communication) | High | The site does not respond over HTTPS; all traffic is carried unencrypted (plaintext) — it can be intercepted/modified, sessions/passwords can be stolen. Fix: valid TLS certificate + HTTP→HTTPS redirect + HSTS. |

## SSL/TLS Configuration Audit

### TLS CERTIFICATE STATUS

⚠️ This target **did not respond over HTTPS (443)**; no valid TLS certificate was found. The site is live only over **unencrypted HTTP**.

### TLS PROTOCOL & CIPHER

- **Active protocol:** could not be detected
- **Cipher:** could not be detected
- **Old/weak version support:** Not observed (only TLS 1.2+ seen)

### HSTS (HTTP Strict Transport Security)

- **Status:** Missing — the browser is not told to enforce HTTPS; there is an SSL-stripping/downgrade attack risk on first requests.

### IDENTIFIED RISKS

| Finding | Severity | Description |
|-------|--------|----------|
| HTTPS not supported (unencrypted communication) | High | The site does not respond over HTTPS; all traffic is carried unencrypted (plaintext). An attacker on the same network can intercept, steal sessions/passwords or modify content. Fix: valid TLS certificate + HTTP→HTTPS redirect + HSTS. |
| HSTS missing | Medium | HTTPS enforcement is not signalled to the browser; open to downgrade attacks. |

## Security Headers & Information Leakage

### HTTP SECURITY HEADERS

| Header | Status | Description |
|--------|-------|----------|
| Strict-Transport-Security | Missing | HTTPS enforcement is not signalled; SSL-stripping risk. |
| Content-Security-Policy | Missing | No browser defence against XSS/injection. |
| X-Frame-Options | Missing | Open to clickjacking; can be embedded in an iframe. |
| X-Content-Type-Options | Missing | MIME-sniffing possible. |
| Referrer-Policy | Missing | Referrer information can leak to external sources. |
| Permissions-Policy | Missing | Sensitive browser APIs are not restricted. |
| X-XSS-Protection | Missing | The legacy-browser XSS filter is not set (not critical in modern browsers). |

### INFORMATION LEAKAGE / EXPOSED FILES

Common sensitive paths were checked with a single GET (content verified — HTTP 200 alone is not counted as evidence):

| Path | Status | Note |
|-----|-------|-----|
| `/.git/config` | Closed | HTTP 400 / empty body — not accessible |
| `/.env` | Closed | HTTP 404 / empty body — not accessible |
| `/.git/HEAD` | Closed | HTTP 400 / empty body — not accessible |
| `/backup.zip` | Closed | HTTP 404 / empty body — not accessible |
| `/.DS_Store` | Closed | HTTP 404 / empty body — not accessible |
| `/wp-config.php.bak` | Closed | HTTP 404 / empty body — not accessible |
| `/ftp` | Closed | HTTP 404 / empty body — not accessible |
| `/backup` | Closed | HTTP 404 / empty body — not accessible |
| `/backups` | Closed | HTTP 404 / empty body — not accessible |
| `/uploads` | Closed | HTTP 404 / empty body — not accessible |
| `/files` | Closed | HTTP 400 / empty body — not accessible |
| `/admin` | Closed | HTTP 404 / empty body — not accessible |
| `/.svn/entries` | Closed | HTTP 400 / empty body — not accessible |
| `/.htaccess` | Closed | HTTP 403 / empty body — not accessible |
| `/config.php.bak` | Closed | HTTP 404 / empty body — not accessible |
| `/db.sql` | ⚠️ OPEN | expected file format verified (not catch-all) |
| `/dump.sql` | Closed | HTTP 404 / empty body — not accessible |

### IDENTIFIED RISKS

| Finding | Severity | Description |
|-------|--------|----------|
| Sensitive file accessible (`/db.sql`) | High | Content verified; configuration/source leakage risk. Access should be blocked immediately. |
| Old/unsupported software version disclosed (PHP/7.1.26 — EOL) | High | The PHP 7.x series is officially unsupported (7.x security updates ended at the end of 2022). Many known vulnerabilities remain unpatched. CWE-1104 · OWASP A06:2021 (Vulnerable and Outdated Components). Fix: upgrade to a current, supported PHP version (8.2+); hide the version signature (expose_php=Off). |
| Outdated software version disclosed (Apache/2.4.25 — very old patch) | Medium | The Apache 2.4 series is supported, but Apache/2.4.25 is a very old patch level; the intervening security patches appear unapplied. CWE-1104 · OWASP A06:2021 (Vulnerable and Outdated Components). Fix: upgrade to the current patch of the 2.4 series; hide the version signature (ServerTokens Prod). |
| Critical security headers missing (Content-Security-Policy, X-Frame-Options) | Medium | Browser defence against XSS/clickjacking is weak. (missing on 2/2 pages) |
| Additional headers missing (Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection) | Medium | Defence in depth is weak. (missing on 2/2 pages) |

## DNS & Email Security

### SPF (Sender Policy) — domain checked: `vulnweb.com`

- **Status:** Present — `v=spf1 ~all`
- **Strictness:** `~all` — soft (softfail; acceptable, not ideal).

### DMARC (Authentication Policy) — domain checked: `vulnweb.com`

- **Status:** Missing — no DMARC record found. No enforcement is applied based on SPF/DKIM results; protection against spoofing is weak.

### DKIM (Signature)

- **Status:** Could not be detected — no DKIM record found at common selectors (default/google/selector1…). You may be using a different selector; this does not definitively mean "none".

### DNSSEC

- **Status:** Passive/none — DNS responses are not signed; more exposed to DNS spoofing/cache-poisoning risk.

### IDENTIFIED RISKS

| Finding | Severity | Description |
|-------|--------|----------|
| DMARC missing | Medium | SPF/DKIM results are not enforced. |
| DKIM could not be detected | Informational | Not found at common selectors (may be a different selector). |
| DNSSEC passive | Informational | DNS responses are not signed. |

## CORS & Cookie Security

### CORS CONFIGURATION (tested on 2/2 pages)

- **Test Origin:** `https://cybertestify-cors-probe.example` — a harmless Origin header was sent to each page and the response evaluated.
- **Most open policy observed** (`/`): Access-Control-Allow-Origin: not sent (closed — safe default); Allow-Credentials: not sent.

### COOKIE FLAGS (all cookies observed on 2 pages)

- No Set-Cookie was observed on any of the 2 scanned pages.

### IDENTIFIED RISKS

- No notable risk stood out in the CORS and cookie configuration.

## CSP (Content Security Policy) Analysis

### CSP STATUS

- **Status:** Missing — the Content-Security-Policy header is never sent.

### CSP DIRECTIVE ANALYSIS

- As there is no CSP applied, directive analysis could not be performed.

### IDENTIFIED RISKS

| Finding | Severity | Description |
|-------|--------|----------|
| CSP entirely missing | Medium | No browser-level defence against XSS and content injection. NO CSP header on ALL 2 pages scanned. |

## POSITIVE ASSURANCE — AREAS CHECKED

Including the areas that produced no finding, the external-surface checks were actually run on **2 unique pages** including the home page. The table below also shows the "no issue found" results transparently:

| Control Area | Result |
|---------------|-------|
| SSL/TLS Configuration Audit | ⚠️ Finding present (High — detailed above) |
| Security Headers & Information Leakage | ⚠️ Finding present (High — detailed above) |
| DNS & Email Security | ⚠️ Finding present (Medium — detailed above) |
| CORS & Cookie Security | ✅ No issue found |
| CSP (Content Security Policy) Analysis | ⚠️ Finding present (Medium — detailed above) |

> **Three-state distinction (honesty):** ✅ *No issue found* = the check ran, came back clean · ⚠️ *Finding present* = detailed above · ⚠️ *Not assessable* = no data collected (does NOT mean secure).

### What this package DOES and does NOT check

**DOES (passive — page fetch via GET + harmless Origin/DNS query only):** TLS/certificate, HTTP security headers, CORS policy, cookie flags (Secure/HttpOnly/SameSite), Content-Security-Policy, DNS/e-mail records (SPF/DKIM/DMARC/DNSSEC), exposed sensitive files, old/unsupported software versions — across the 2 discovered pages.

**DOES NOT:** Active vulnerability verification (payload/probe attempts such as SQLi/XSS/IDOR), authenticated-flow testing, business-logic exploitation. These are within the scope of the **Active Verification** and **Full-Scope Pentest** packages. This report is based on passive observation; "no finding" in an area **does NOT prove** it is secure, because no active exploitation was attempted — it only shows that the externally observed configuration is clean.
