## EXECUTIVE SUMMARY

- **Overall risk level: High** — the site does not support HTTPS; communication is carried unencrypted (plaintext) — it can be intercepted/modified. Migrating to HTTPS should be the priority.
- ⚠️ This target did not respond over HTTPS (443); the scan was performed **over http://**. The lack of HTTPS is a finding on its own (below).
- 6/6 important security headers are missing: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy, Permissions-Policy.
- **Scope:** The security-header and version-signature checks were run on **8 unique pages** including the home page (not just a single page).
- **Recommended first step:** Install a valid TLS certificate and move all traffic to HTTPS; ready-made step-by-step commands are provided in the "AI Solution Recommendations" add-on.

> **Scope and limits:** This package is a **passive, GET-based** external observation; no active exploitation or probe was attempted. A "no finding" statement in an area **does NOT prove** it is secure, because no active test was performed — it only shows that the externally observed configuration is clean.

## OVERALL ASSESSMENT

**Risk level: High**

This target does not respond over HTTPS; communication runs unencrypted (plaintext) over HTTP. This is a serious gap that allows an attacker on the same network to intercept/modify traffic and steal sessions/passwords; modern browsers mark the site as "Not secure". The priority is to migrate to HTTPS with a valid TLS certificate and add an HTTP→HTTPS redirect + HSTS. The other header checks were performed over http://.

## HTTP SECURITY HEADERS

| Header | Status | Description |
|--------|-------|----------|
| Strict-Transport-Security | Missing | The browser is not told to enforce HTTPS; there is an SSL-stripping/MITM risk on first requests. |
| Content-Security-Policy | Missing | The browser cannot restrict which resources are loaded; there is no basic defence against XSS and content injection. |
| X-Frame-Options | Missing | The page can be embedded in another site's iframe; the user can be tricked via clickjacking. |
| X-Content-Type-Options | Missing | The browser may guess the content type (MIME-sniffing); uploaded files could run as scripts. |
| Referrer-Policy | Missing | The full URL (Referer) is sent to external links; session/privacy information can leak. |
| Permissions-Policy | Missing | Sensitive APIs such as camera/microphone/location are not restricted; third-party content could abuse them. |
| X-XSS-Protection | Missing | The legacy-browser XSS filter is not set (not critical in modern browsers; the real protection is the CSP). |
| Content-Type | Present | text/html |

## TLS CERTIFICATE STATUS

⚠️ This target **did not respond over HTTPS (443)**; no valid TLS certificate was found. The site is live only over **unencrypted HTTP** (see Identified Risks → "HTTPS not supported"). The header checks below were performed over http://.

## SERVER / TECHNOLOGY SIGNATURE

- Server: Microsoft-IIS/8.5
- X-Powered-By: ASP.NET

## IDENTIFIED RISKS

| Finding | Severity | Description |
|-------|--------|----------|
| HTTPS not supported (unencrypted communication) | High | The site does not respond over HTTPS; all traffic to/from the page is carried unencrypted (plaintext) — an attacker on the same network can intercept the traffic, steal sessions/passwords or modify content. The scan was performed over http://. |
| Critical security headers missing (Content-Security-Policy, X-Frame-Options) | Medium | There is no browser-level defence against XSS and/or clickjacking attacks. Missing on ALL 8 unique pages scanned. |
| Additional security headers missing (X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy, Permissions-Policy) | Medium | Defence in depth is weak; individually low-impact, but together they widen the attack surface. Missing on ALL 8 unique pages scanned. |

## POSITIVE ASSURANCE — AREAS CHECKED

Including the areas that produced no finding, the Basic Scan checks were actually run on **8 unique pages** including the home page. The table below also shows the "no issue found" results transparently:

| Control Area | Result |
|---------------|-------|
| HTTP security headers (on 8 pages) | ⚠️ Finding present (6/6 recommended headers missing — detailed above) |
| TLS / certificate | ⚠️ Finding present (HTTPS did not respond — unencrypted communication) |
| Server/software version signature (on 8 pages) | ✅ No issue found (no known old/EOL version signature detected) |

> **Three-state distinction (honesty):** ✅ *No issue found* = the check ran, came back clean · ⚠️ *Finding present* = detailed above · ⚠️ *Not assessable* = no data collected (does NOT mean secure).

### What this package DOES and does NOT check

**DOES (passive — page fetch via GET only, no probe/payload is sent):** HTTP security headers, TLS/certificate status (validity · hostname · TLS version), server-software version signature and known old/EOL version detection — across the 8 discovered pages.

**DOES NOT:** CORS policy, cookie flag detail, Content-Security-Policy analysis, DNS/e-mail records (SPF/DKIM/DMARC) and exposed sensitive-file scanning are in the **External Surface** package; GDPR/PCI/ISO framework mapping is in the **Compliance** package; subdomain/API/CVE discovery is in the **Reconnaissance** package; active vulnerability verification (SQLi/XSS/IDOR probing) is addressed in the **Active Verification** and **Full-Scope Pentest** packages. This report is based on passive observation; "no finding" **does NOT prove** it is secure, because no active exploitation was attempted.
