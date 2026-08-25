This section contains remediation recommendations for the findings detected in the active verification checks that were run.

### Injection (SQLi/XSS) Verification

### Injection (SQLi/XSS) — remediation

- **SQLi:** Write all database queries with **parameterised queries / prepared statements**; never concatenate user input into the query as a string. If you use an ORM, avoid raw SQL concatenation. Do not show database error messages to the end user.
- **XSS:** Apply **context-appropriate output encoding** (HTML entity encoding) when printing user input to HTML; where possible use a template engine that auto-escapes. Restrict inline scripts with a `Content-Security-Policy` header.
- After remediation, re-test the same input points.

### Broken Access Control (IDOR) Verification

### Broken Access Control (IDOR) — remediation

- **Object-level authorization:** On every resource access, verify server-side whether the requesting user has the right to access that object (a valid ID alone is not enough).
- **Unpredictable identifiers:** Use UUIDs/random identifiers instead of sequential numeric IDs; make enumeration harder.
- Place resources that should not be public behind authentication.

### SSRF Verification

### SSRF — proactive hardening

- Apply a server-side **allowlist** + internal-network blocking on all fields that accept a URL from the user (proactive).
- When an external fetch is required, add scheme/host validation + timeout + size limit.

### File Upload Verification

### File Upload — proactive hardening

- Apply server-side type/MIME validation + allowlist + storage outside the web root at upload endpoints (proactive).

### Business Logic Verification

### Business Logic — proactive hardening

- Validate critical values (price/quantity) server-side; apply step-order control in multi-step flows (proactive).

### Race / Mass-Assignment Verification

### Race / Mass-Assignment — proactive hardening

- Apply a field allowlist (mass-assignment protection) in model binding; use an atomic/idempotent design in critical operations (proactive).

### RCE / Command Injection Verification

### RCE / Command Injection — proactive hardening

- Review code paths that call system commands; validate input with an allowlist, avoid shell string concatenation (proactive).
- Apply least privilege + outbound network restriction.

### Login Bypass (SQLi Indicator)

### Login Bypass / SQL Injection — remediation

- Use **parameterised queries / prepared statements** in authentication queries; never place user input directly into SQL.
- Input validation + safe ORM APIs; return a uniform error message on failed login.
