## EXECUTIVE SUMMARY

- **Overall risk level: High** — 3 areas examined; the highest risk is in the **CMS & known CVE Scan** area (No known CMS fingerprint detected · 21 known CVEs in the server/software version).
- ⚠️ **HTTPS not supported:** The target did not respond over HTTPS (443); reconnaissance was carried out over http://. Unencrypted communication is a serious finding in itself (see below).
- **Subdomain Takeover Scan:** Low — No subdomain seen in the Certificate Transparency records
- **API & Swagger Reconnaissance:** Low — No publicly accessible API/Swagger documentation found
- **CMS & known CVE Scan:** High — No known CMS fingerprint detected · 21 known CVEs in the server/software version
- **Scope (real numbers):** 0 subdomains inventoried · 12 API/Swagger paths checked (2 pages scanned) · 6+ passive CMS/technology signals examined.
- **Recommended first step:** Start with the highest-risk area; step-by-step ready-made solutions for each finding are provided in the “AI Solution Suggestions” section.

## OVERALL ASSESSMENT

**Risk Level: High**

This target does not respond over HTTPS; communication is carried unencrypted (HTTPS should be adopted as a priority). The highest risk was detected in the **CMS & known CVE Scan** area (No known CMS fingerprint detected · 21 known CVEs in the server/software version); priority remediation is recommended. Each area is reported separately below.

## IDENTIFIED RISKS

| Finding | Severity | Description |
|-------|--------|----------|
| HTTPS not supported (unencrypted communication) | High | The target does not respond over HTTPS; all traffic is carried unencrypted (plaintext) — interceptable/modifiable. Solution: valid TLS certificate + HTTP→HTTPS redirect + HSTS. |
| CMS & known CVE Scan — No known CMS fingerprint detected · 21 known CVEs in the server/software version | High | See the “CMS & known CVE Scan” section below for details. |

## SCOPE & METHODOLOGY

This report was generated automatically from externally observable data using **passive** (non-exploitative) techniques across three reconnaissance areas:

- **Subdomain Takeover:** Subdomains are collected from Certificate Transparency logs (crt.sh, with certSpotter as a fallback); each is put through DNS/CNAME resolution via Cloudflare DoH and compared against a signature database of known “dangling” (abandoned cloud services).
- **API & Swagger Reconnaissance:** A fixed list of common API documentation paths is checked via GET; any OpenAPI/Swagger schemas found are parsed and sensitive/unauthenticated endpoints are flagged (the endpoints are not called).
- **CMS & known CVE:** CMS and version fingerprinting is derived from HTTP headers, `<meta generator>` and HTML patterns; if the generator is hidden, it is verified via the EXISTENCE of known CMS paths (GET/existence only — no login attempt). The detected version is matched against known CVEs that explicitly cover the version by querying the NVD (NIST National Vulnerability Database); if the version cannot be read, no CVE mapping is performed (no fabricated CVEs).

> All data was collected externally, without causing harm to the target. Authentication-protected areas, the internal network and active exploitation are outside the scope of this package.

## Subdomain Takeover Scan

**Overall risk level: Low — No subdomain seen in the Certificate Transparency records**

From the Certificate Transparency records (crt.sh / certSpotter), **0** unique subdomains were inventoried; of these, the CNAME record of **0** was resolved and examined for takeover (subdomain takeover).

No **takeover-able (dangling)** subdomain pointing to an abandoned cloud resource was detected among the resolved CNAME records. This indicates that your externally visible subdomain surface currently appears **narrow and controlled**.

> Scope: Passive sources only (Certificate Transparency logs + observable DNS). No subdomain brute-force / active scan was performed.

## API & Swagger Reconnaissance

**Overall risk level: Low — No publicly accessible API/Swagger documentation found**

The following **12** common API documentation/discovery paths were checked via GET. No endpoint was called/exploited (passive reconnaissance).

### Paths checked (full list)

| Path | HTTP | Status |
|-----|------|-------|
| /openapi.json | 404 | Not found |
| /swagger.json | 404 | Not found |
| /v2/api-docs | 400 | Not found |
| /v3/api-docs | 400 | Not found |
| /api-docs | 404 | Not found |
| /api/docs | 400 | Not found |
| /api/v1/docs | 400 | Not found |
| /swagger-ui.html | 404 | Not found |
| /swagger/index.html | 400 | Not found |
| /redoc | 404 | Not found |
| /.well-known/openapi.json | 400 | Not found |
| /graphql | 404 | Not found |

None of the paths checked returned a publicly accessible API schema/interface. The absence of public API documentation means attackers cannot easily **map** your API surface from outside — this is a positive sign for the external attack surface.

> Scope: Only publicly accessible documentation paths were checked via GET; no endpoint was called/exploited (passive reconnaissance).

## CMS & known CVE Scan

**Overall risk level: High — No known CMS fingerprint detected · 21 known CVEs in the server/software version**

### Fingerprint sources examined

For CMS/framework and version detection, the following passive signals in the home page response were examined:

- HTTP response headers (`Server`, `X-Powered-By`, `X-Generator`, `X-Drupal-Cache`, `X-Magento-Cache-Debug`)
- `<meta name="generator">` tag
- HTML path/pattern traces (`/wp-content/`, `/wp-includes/`, `Drupal.settings`, `/sites/all/`, `option=com_`, `/media/jui/`, `typo3conf`, `Magento_`)
- Common version files (WordPress `/readme.html`, Drupal `/CHANGELOG.txt`)
- EXISTENCE of known CMS paths (`/wp-login.php`, `/wp-json/`, `/administrator/`, `/user/login`, `/typo3/` — presence/absence check only; NO login/password attempt)
- Library/plugin hints (WooCommerce, jQuery version)

**None** of these signals matched a known CMS/framework. This suggests a custom-built application or an installation that deliberately hides CMS traces; either case makes automatic CMS/CVE mapping from outside harder.

### Server/Software Banner Version — Known CVE (NVD)

The version(s) derived from the banner were matched against the NVD (NO exploitation/verification — only the "are there known CVEs for this version" indicator):

| Software/Version | NVD result | Example CVE |
|-----|-------|-------|
| Apache httpd 2.4.25 | not queryable (NOT clean) | — |
| PHP 7.1.26 | ⚠️ 21 known CVEs | [CVE-2017-8923](https://nvd.nist.gov/vuln/detail/CVE-2017-8923) |

> **Note:** The CVE list below contains known vulnerabilities that were **automatically mapped via the NVD (NIST National Vulnerability Database)** from the detected version; whether they are exploitable for your version is **not verified**, and some may originate from plugins/themes. For a confirmed assessment, an update + targeted verification are recommended.

> Scope: Passive fingerprint + known-CVE mapping via the NVD. No CVE was **exploited/verified**.

## POSITIVE ASSURANCE — RECONNAISSANCE METHODS CHECKED

Reconnaissance comes out clean on most healthy targets; this section also makes the “nothing found” result TRANSPARENT — it shows what was ACTUALLY checked (including a **2-page** sitemap, home page included):

| Reconnaissance Area | Result |
|-------------|-------|
| Subdomain Takeover Scan | ✅ 0 subdomain records checked; no takeover indicator found |
| API & Swagger Reconnaissance | ✅ 12 paths checked (12 fixed + 0 sitemap candidates, from 2 pages); no publicly accessible API schema found |
| CMS / Framework CVE Match | ✅ No known CMS/framework fingerprint detected |

> **Three-state distinction (honesty):** ✅ *No indicator found* = method ran, clean · ⚠️ *Indicator present* = detailed above · ⚠️ *Not assessable* = no data collectable (does NOT mean secure).

### What this package assesses — and what it does NOT

**ASSESSES (passive reconnaissance — GET only, external sources):** subdomain inventory + takeover (dangling CNAME), publicly accessible API/Swagger/OpenAPI document, CMS/framework and server/software banner (Apache/nginx/PHP) fingerprint + known CVE match (NVD), EXISTENCE determination of API/administrative-looking paths derived from the sitemap + robots.txt Disallow entries — across 2 pages.

**DOES NOT ASSESS:** active injection/IDOR/XSS verification and authorisation testing of discovered endpoints (**Active Verification / Full Pentest** scope), HTTP security header/CORS/cookie/CSP details (**Basic Scan / External Attack Surface** scope), GDPR/PCI/ISO framework mapping (**Compliance** scope). The statement “no indicator found” in an area **DOES NOT PROVE** you are secure — it only shows that no indicator emerged with the passive methods checked.

## BEST PRACTICES / RECOMMENDED NEXT STEPS

Regardless of the outcome of this scan, the following are recommended lasting practices to keep your attack surface narrow:

- **Clean up unused CNAME records regularly** — records pointing to abandoned cloud resources carry a subdomain takeover risk; remove the DNS record before deleting the cloud resource.
- **If you have API documentation (Swagger/OpenAPI),** keep it open only to authenticated access; do not publish it publicly in production.
- **Keep your CMS, plugin and theme versions** up to date via auto-update or regular tracking; stay patched against known CVEs.
- **Detect new/unexpected subdomain certificates early** with Certificate Transparency (CT) log monitoring tools (crt.sh, certSpotter, etc.).
- **Reduce version/technology disclosure** — do not leak unnecessary version information through headers/tags such as `Server`, `X-Powered-By`, `<meta generator>`.
- **Document your subdomain inventory** — knowing which subdomain belongs to which service/team helps you quickly spot idle records.
