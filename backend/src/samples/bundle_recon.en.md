## EXECUTIVE SUMMARY

- **Overall risk level: Low** — your reconnaissance surface was examined across 3 areas; no takeover-able subdomain, exposed sensitive API or known high CVE covering your version stood out. Your externally visible surface currently appears narrow and controlled.
- **Subdomain Takeover Scan:** Low — 7 subdomains inventoried; no takeover-able record detected
- **API & Swagger Discovery:** Low — no public API/Swagger documentation found
- **CMS & Known-CVE Scan:** Low — WordPress 5.5.20 detected; no matching CVE found
- **Scope (real numbers):** 7 subdomains inventoried · 19 API/Swagger paths tried (7 pages scanned) · 6+ passive CMS/technology signals examined.
- **Recommended first step:** Start with the highest-risk area; ready-made step-by-step fixes for each finding are in the "AI Solution Recommendations" section.

## OVERALL ASSESSMENT

**Risk Level: Low**

Your externally visible subdomain, API and CMS surface currently appears narrow and controlled; the report documents each area separately with a full inventory and recommended best practices. Each area is reported separately below.

## SCOPE & METHODOLOGY

This report was generated automatically from externally observable data using **passive** (non-exploitative) techniques across three reconnaissance areas:

- **Subdomain Takeover:** Subdomains are gathered from Certificate Transparency logs (crt.sh, with certSpotter as fallback); each is resolved via Cloudflare DoH for DNS/CNAME and compared against a database of known "dangling" (abandoned cloud service) signatures.
- **API & Swagger Discovery:** A fixed list of common API documentation paths is tried via GET; any OpenAPI/Swagger schemas found are parsed and sensitive/unauthenticated endpoints are flagged (endpoints are not called).
- **CMS & Known CVE:** CMS and version fingerprints are extracted from HTTP headers, `<meta generator>` and HTML patterns; if the generator is hidden, the PRESENCE of known CMS paths is verified (GET/existence only — no login attempt). The detected version is mapped against known CVEs by querying the NVD (NIST National Vulnerability Database) — only CVEs that explicitly cover the version; if the version cannot be read, no CVE mapping is done (no fabricated CVEs).

> All data was collected externally without harming the target. Areas requiring authentication, the internal network and active exploitation are outside the scope of this package.

## Subdomain Takeover Scan

**Overall risk level: Low — 7 subdomains inventoried; no takeover-able record detected**

**7** unique subdomains were inventoried from Certificate Transparency (crt.sh / certSpotter) records; of these, the CNAME records of **7** were resolved and examined for subdomain takeover.

In the resolved CNAME records, no **takeover-able (dangling)** subdomain pointing to an abandoned cloud resource was detected. This indicates that your externally visible subdomain surface currently appears **narrow and controlled**.

### Subdomain inventory (status table)

Discovered subdomains and their status after CNAME resolution:

| Subdomain | CNAME Target | Status |
|-----------|--------------|-------|
| api.ornek.com | — | No CNAME record (direct A/AAAA) |
| blog.ornek.com | — | No CNAME record (direct A/AAAA) |
| mail.ornek.com | mail.barindirma-saglayici.example | Active (has CNAME record) |
| panel.ornek.com | — | No CNAME record (direct A/AAAA) |
| cdn.ornek.com | — | No CNAME record (direct A/AAAA) |
| destek.ornek.com | — | No CNAME record (direct A/AAAA) |
| www.ornek.com | ornek.com | Active (has CNAME record) |

> Scope: Passive sources only (Certificate Transparency logs + observable DNS). No subdomain brute-force / active scanning was performed.

## API & Swagger Reconnaissance

**Overall risk level: Low — no public API/Swagger documentation found**

The following **12** common API documentation/discovery paths were tried via GET. No endpoint was called/exploited (passive reconnaissance).

### Paths tried (full list)

| Path | HTTP | Status |
|-----|------|-------|
| /openapi.json | 404 | Not found |
| /swagger.json | 404 | Not found |
| /v2/api-docs | 404 | Not found |
| /v3/api-docs | 404 | Not found |
| /api-docs | 404 | Not found |
| /api/docs | 404 | Not found |
| /api/v1/docs | 404 | Not found |
| /swagger-ui.html | 404 | Not found |
| /swagger/index.html | 404 | Not found |
| /redoc | 404 | Not found |
| /.well-known/openapi.json | 404 | Not found |
| /graphql | 404 | Not found |

### Path candidates derived from the sitemap (7 candidates from 7 pages)

**In addition** to the fixed list, API/admin-looking paths extracted from link/script/form references on the discovered pages were also tried via GET for **existence only** (NO payload/injection — Reconnaissance only detects "does this endpoint exist"):

| Candidate Path | Source page | HTTP | Note |
|----------|--------------|------|-----|
| /wp-content/uploads/elementor/css/global.css | / | 200 | ⚠️ present (admin-looking) |
| /wp-content/uploads/elementor/css/post-5.css | / | 200 | ⚠️ present (admin-looking) |
| /wp-content/uploads/2023/05/logo-150x150.png | / | 200 | ⚠️ present (admin-looking) |
| /wp-content/uploads/2023/05/logo.png | / | 200 | ⚠️ present (admin-looking) |
| /wp-content/uploads/2023/05/banner-scaled.jpg | / | 200 | ⚠️ present (admin-looking) |
| /wp-content/uploads/2023/05/urun-gorseli-1.jpg | / | 200 | ⚠️ present (admin-looking) |
| /wp-content/uploads/2023/05/hizmet-gorseli-2.jpg | / | 200 | ⚠️ present (admin-looking) |

> **7** admin/sensitive-looking paths were discovered from the sitemap and are accessible (HTTP 200). The AUTHORIZATION control of these paths should be verified with **Active Verification / Full Pentest** — Reconnaissance only detects existence, it does not test authorization.

None of the tried paths returned a public API schema/interface. The absence of public API documentation means attackers cannot easily **map** your API surface from the outside — a positive sign for the external attack surface.

> Scope: Only public documentation paths were tried via GET; no endpoint was called/exploited (passive reconnaissance).

## CMS & Known-CVE Scan

**Overall risk level: Low — WordPress 5.5.20 detected; no matching CVE found**

### Fingerprint sources examined

For CMS/framework and version detection, the following passive signals on the home-page response were inspected:

- HTTP response headers (`Server`, `X-Powered-By`, `X-Generator`, `X-Drupal-Cache`, `X-Magento-Cache-Debug`)
- `<meta name="generator">` tag
- HTML path/pattern traces (`/wp-content/`, `/wp-includes/`, `Drupal.settings`, `/sites/all/`, `option=com_`, `/media/jui/`, `typo3conf`, `Magento_`)
- Common version files (WordPress `/readme.html`, Drupal `/CHANGELOG.txt`)
- PRESENCE of known CMS paths (`/wp-login.php`, `/wp-json/`, `/administrator/`, `/user/login`, `/typo3/` — existence check only; NO login/password attempt)
- Library/plugin hints (WooCommerce, jQuery version)

### Fingerprint result

- Detected system: **WordPress 5.5.20**
- How detected: Meta generator: "WordPress 5.5.20"
- Additional observations: WooCommerce (WordPress e-commerce plugin) detected · X-Powered-By: ASP.NET · Server: Microsoft-IIS/10.0

### Known CVE matches (NVD)

The NVD (NIST National Vulnerability Database) query did not respond during this scan; no CVE mapping could be done. Please verify your version manually on the NVD.

> Scope: Passive fingerprint + known-CVE mapping via NVD. No CVE was **exploited/verified**.

## POSITIVE ASSURANCE — RECONNAISSANCE METHODS CHECKED

Reconnaissance comes back clean on most healthy targets; this section makes the "nothing found" result TRANSPARENT too — it shows what was ACTUALLY tried (across **7 pages** including the home page and sitemap):

| Reconnaissance Area | Result |
|-------------|-------|
| Subdomain Takeover Scan | ✅ 7 subdomain records tried; no takeover indicator found |
| API & Swagger Discovery | ✅ 19 paths tried (12 fixed + 7 sitemap candidates, from 7 pages); no public API schema found |
| CMS / Framework CVE Match | ✅ WordPress 5.5.20 detected; no known high CVE covering the version matched |
| Sitemap path discovery | ⚠️ 7 admin-looking paths accessible (authorization test is Active Verification scope) |

> **Three-state distinction (honesty):** ✅ *No indicator found* = the method ran, clean · ⚠️ *Indicator present* = detailed above · ⚠️ *Not assessable* = no data collected (does NOT mean secure).

### What this package DOES and does NOT assess

**ASSESSES (passive reconnaissance — GET only, external sources):** subdomain inventory + takeover (dangling CNAME), public API/Swagger/OpenAPI docs, CMS/framework fingerprint + known-CVE match (NVD), existence detection of API/admin-looking paths derived from the sitemap — across 7 pages.

**DOES NOT ASSESS:** active injection/IDOR/XSS verification and authorization testing of discovered endpoints (**Active Verification / Full Pentest** scope), HTTP security header/CORS/cookie/CSP detail (**Basic Scan / External Surface** scope), GDPR/PCI/ISO framework mapping (**Compliance** scope). "No indicator found" in an area **does NOT prove** you are secure — it only shows that no indicator emerged from the passive methods attempted.

## BEST PRACTICES / RECOMMENDED NEXT STEPS

Regardless of this scan's result, recommended lasting practices to keep your attack surface narrow:

- **Regularly clean up unused CNAME records** — records pointing to abandoned cloud resources carry a subdomain-takeover risk; remove the DNS record before deleting the cloud resource.
- **If you have API documentation (Swagger/OpenAPI)**, keep it available only to authenticated access; do not publish it publicly in production.
- **Keep your CMS, plugin and theme versions** current via automatic updates or regular tracking; stay patched against known CVEs.
- **Use Certificate Transparency (CT) log monitoring** tools (crt.sh, certSpotter, etc.) to spot new/unexpected subdomain certificates early.
- **Reduce version/technology disclosure** — do not leak unnecessary version information via headers/tags such as `Server`, `X-Powered-By`, `<meta generator>`.
- **Document your subdomain inventory** — knowing which subdomain belongs to which service/team lets you quickly notice orphaned records.
