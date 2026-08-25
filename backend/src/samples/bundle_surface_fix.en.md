This section contains area-by-area remediation suggestions for all the gaps detected in your external-surface scan. Copy the examples that suit your server (Nginx/Firebase/Apache/DNS).

### SSL/TLS Configuration Audit

The following recommendations strengthen the TLS/encryption configuration for rest.vulnweb.com.

### 1. Add the HSTS header

Tells the browser to connect to the site only over HTTPS (apply only if your site runs entirely over HTTPS):

**Nginx:**

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

**Firebase Hosting — `firebase.json`:**

```json
{
  "hosting": {
    "headers": [
      {
        "source": "**",
        "headers": [
          { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains" }
        ]
      }
    ]
  }
}
```

**Apache — `.htaccess`:**

```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

### Security Headers & Information Leakage

The following recommendations address the missing security headers detected on the home page of rest.vulnweb.com. Each header has a short explanation followed by an Nginx example; at the end you will find ready-made blocks for non-Nginx platforms (Firebase, Vercel, Next.js, Apache). Copy the one that suits your server.

### 1. Add a Content-Security-Policy (CSP)

This is the most effective browser-level defence against XSS and content injection. Start with a baseline policy suited to your site and tighten it over time:

```nginx
add_header Content-Security-Policy "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'" always;
```

If you use third-party scripts (GTM, Analytics, Pixel), add the relevant domains to `script-src`/`connect-src`.

### 2. Add X-Frame-Options

Prevents your page from being embedded in another site’s iframe and exposed to clickjacking:

```nginx
add_header X-Frame-Options "SAMEORIGIN" always;
```

As a modern alternative, CSP `frame-ancestors 'self'` provides the same protection.

### 3. Add X-Content-Type-Options

Prevents the browser from MIME-type sniffing and misinterpreting content (and the XSS risk that follows):

```nginx
add_header X-Content-Type-Options "nosniff" always;
```

### 4. Add Strict-Transport-Security (HSTS)

Enforces HTTPS and makes SSL-stripping/MITM attacks harder. (Apply only if your site runs entirely over HTTPS.)

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

### 5. Add Referrer-Policy

Reduces information leakage via the `Referer` header sent to external links:

```nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

### 6. Add Permissions-Policy

Restricts browser APIs (camera, microphone, location, etc.) and prevents unwanted access by third-party iframes:

```nginx
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

### 7. X-XSS-Protection (defence-in-depth)

A legacy header for older browsers; the real protection lies in CSP. You may add it optionally:

```nginx
add_header X-XSS-Protection "1; mode=block" always;
```

### Combined configuration — Nginx

Add these to your server block (server { ... }), verify with `nginx -t`, then reload with `systemctl reload nginx`:

```nginx
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'self'" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

### Ready-made configuration for other platforms

If your server is not Nginx, you can add the same headers using one of the ready-made blocks below.

**Firebase Hosting — `firebase.json`:**

```json
{
  "hosting": {
    "headers": [
      {
        "source": "**",
        "headers": [
          { "key": "Content-Security-Policy", "value": "default-src 'self'; frame-ancestors 'self'" },
          { "key": "X-Frame-Options", "value": "SAMEORIGIN" },
          { "key": "X-Content-Type-Options", "value": "nosniff" },
          { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains" },
          { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
          { "key": "Permissions-Policy", "value": "geolocation=(), microphone=(), camera=()" }
        ]
      }
    ]
  }
}
```

**Vercel — `vercel.json`:**

```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
          { "key": "Content-Security-Policy", "value": "default-src 'self'; frame-ancestors 'self'" },
          { "key": "X-Frame-Options", "value": "SAMEORIGIN" },
          { "key": "X-Content-Type-Options", "value": "nosniff" },
          { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains" },
          { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
          { "key": "Permissions-Policy", "value": "geolocation=(), microphone=(), camera=()" }
      ]
    }
  ]
}
```

**Next.js — `next.config.js`:**

```js
module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'Content-Security-Policy', value: 'default-src 'self'; frame-ancestors 'self'' },
          { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'geolocation=(), microphone=(), camera=()' }
        ],
      },
    ];
  },
};
```

**Apache — `.htaccess` (mod_headers):**

```apache
Header always set Content-Security-Policy "default-src 'self'; frame-ancestors 'self'"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
```

**IIS / ASP.NET — `web.config`:**

```xml
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
      <add name="Content-Security-Policy" value="default-src 'self'; frame-ancestors 'self'" />
      <add name="X-Frame-Options" value="SAMEORIGIN" />
      <add name="X-Content-Type-Options" value="nosniff" />
      <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
      <add name="Referrer-Policy" value="strict-origin-when-cross-origin" />
      <add name="Permissions-Policy" value="geolocation=(), microphone=(), camera=()" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
```

After making the changes, verify with your browser developer tools (Network tab) or `curl -I https://rest.vulnweb.com` that the headers are present in the response.

### Block access to exposed files

Detected paths: `/db.sql`. Block access at the server level:

**Nginx:**

```nginx
location ~ /\.(git|env|ht) { deny all; return 404; }
location ~* \.(bak|old|zip|sql)$ { deny all; return 404; }
```

**Apache — `.htaccess`:**

```apache
RedirectMatch 404 /\.git
RedirectMatch 404 /\.env
<FilesMatch "\.(bak|old|zip|sql)$">
  Require all denied
</FilesMatch>
```

It is also best not to place these files in the web root (public) at all.

### DNS & Email Security

The following recommendations strengthen email authentication for the domain vulnweb.com. Add the records via your DNS provider's (Cloudflare/GoDaddy/…) TXT interface.

### Add/harden a DMARC record

First monitor with `p=none`; once you have reviewed the reports and ruled out false positives, move to `quarantine` → `reject`:

```dns
_dmarc.vulnweb.com.  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@vulnweb.com; fo=1"
```

### Enable DKIM signing

Generate DKIM from your email provider's panel (Google Workspace/Microsoft 365/sending service) and add the TXT record it provides under `selector._domainkey`:

```dns
google._domainkey.vulnweb.com.  TXT  "v=DKIM1; k=rsa; p=<key-provided-by-your-provider>"
```

### Enable DNSSEC

Turn on **DNSSEC** in your DNS provider's panel; the provider generates the DS record, which you enter at your domain registrar. It signs DNS responses and makes cache poisoning harder.

### CORS & Cookie Security

The following recommendations strengthen CORS and cookie security for rest.vulnweb.com.

Your CORS and cookie configuration is close to secure defaults. When adding new endpoints, keep the origin-allowlist and cookie-flag (Secure/HttpOnly/SameSite) principle.

### CSP (Content Security Policy) Analysis

The following recommendations strengthen the Content-Security-Policy for rest.vulnweb.com. Test the CSP first with the `Content-Security-Policy-Report-Only` header, and only switch to the enforced header once you are sure the site is not broken.

### Baseline (starter) CSP

Extend it by adding your own third-party domains (analytics, CDN, fonts) to `script-src`/`connect-src`/`img-src`:

**Nginx:**

```nginx
add_header Content-Security-Policy "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'" always;
```

**Firebase Hosting — `firebase.json`:**

```json
{
  "hosting": {
    "headers": [
      {
        "source": "**",
        "headers": [
          { "key": "Content-Security-Policy", "value": "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'" }
        ]
      }
    ]
  }
}
```

**Apache — `.htaccess`:**

```apache
Header always set Content-Security-Policy "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'"
```

### Test with Report-Only

```
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report
```

After monitoring the reports and clearing false positives, publish the header as `Content-Security-Policy`.