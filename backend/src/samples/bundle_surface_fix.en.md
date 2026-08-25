This section contains area-by-area remediation recommendations for every gap detected in your external-surface scan. Copy the examples that fit your server (Nginx/Firebase/Apache/DNS).

### SSL/TLS Configuration Audit

The recommendations below strengthen the TLS/encryption configuration for rest.vulnweb.com.

### 1. Add the HSTS header

Tells the browser to connect to the site only over HTTPS (apply only if your site is fully HTTPS):

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

The recommendations below aim to fix the missing security headers detected on the rest.vulnweb.com home page. For each header, a short explanation is given first, followed by an Nginx example; at the end you will find ready-made blocks for non-Nginx platforms (Firebase, Vercel, Next.js, Apache). Copy the one that fits your server.

### 1. Add Content-Security-Policy (CSP)

This is the most effective browser defence against XSS and content injection. Start with a basic policy suited to your site and tighten it over time:

```nginx
add_header Content-Security-Policy "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'" always;
```

If you use third-party scripts (GTM, Analytics, Pixel), add the relevant domains to `script-src`/`connect-src`.

### 2. Add X-Frame-Options

Prevents your page from being embedded in another site's iframe and exposed to clickjacking:

```nginx
add_header X-Frame-Options "SAMEORIGIN" always;
```

As a modern alternative, CSP `frame-ancestors 'self'` provides the same protection.

### 3. Add X-Content-Type-Options

Prevents the browser from MIME-type sniffing and misinterpreting content (and the XSS risk it opens):

```nginx
add_header X-Content-Type-Options "nosniff" always;
```

### 4. Add Strict-Transport-Security (HSTS)

Enforces HTTPS and makes SSL-stripping/MITM attacks harder. (Apply only if your site is fully HTTPS.)

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

### 5. Add Referrer-Policy

Reduces information leakage in the `Referer` header sent to external links:

```nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

### 6. Add Permissions-Policy

Restricts browser APIs (camera, microphone, location, etc.); prevents unwanted access by third-party iframes:

```nginx
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

### 7. X-XSS-Protection (defence in depth)

A historical header for old browsers; the real protection is in the CSP. You may add it optionally:

```nginx
add_header X-XSS-Protection "1; mode=block" always;
```

### Combined configuration — Nginx

Add it to your server block (server { ... }), validate with `nginx -t`, then reload with `systemctl reload nginx`:

```nginx
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'self'" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

### Ready-made configuration for other platforms

If your server is not Nginx, you can add the same headers with the appropriate ready-made block below.

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

After the changes, verify the headers are added to the response using the browser developer tools (Network tab) or `curl -I https://rest.vulnweb.com`.

### Block access to exposed files

Detected paths: `/db.sql`. Close access at the server level:

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

It is also healthiest never to place these files in the web root (public) at all.

### DNS & Email Security

The recommendations below strengthen e-mail authentication for the vulnweb.com domain. Add the records via the TXT interface of your DNS provider (Cloudflare/GoDaddy/…).

### Add/tighten the DMARC record

First monitor with `p=none`, review the reports, and once you are sure there are no false positives, move to `quarantine` → `reject`:

```dns
_dmarc.vulnweb.com.  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@vulnweb.com; fo=1"
```

### Enable DKIM signing

Generate DKIM from your e-mail provider's panel (Google Workspace/Microsoft 365/sending service) and add the TXT record it gives you under `selector._domainkey`:

```dns
google._domainkey.vulnweb.com.  TXT  "v=DKIM1; k=rsa; p=<the-key-your-provider-gives>"
```

### Enable DNSSEC

Turn on **DNSSEC** from your DNS provider's panel; the provider generates the DS record, which you enter at your domain registrar. It signs DNS responses and makes cache-poisoning harder.

### CORS & Cookie Security

The recommendations below strengthen CORS and cookie security for rest.vulnweb.com.

Your CORS and cookie configuration is close to safe defaults. When adding new endpoints, keep the principle of an origin allowlist and cookie flags (Secure/HttpOnly/SameSite).

### CSP (Content Security Policy) Analysis

The recommendations below strengthen the Content-Security-Policy for rest.vulnweb.com. First test the CSP with the `Content-Security-Policy-Report-Only` header, and once you are sure it does not break the site, move to the enforced header.

### Basic (starter) CSP

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

### Testing with Report-Only

```
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report
```
