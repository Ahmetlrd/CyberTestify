## MANAGEMENTZUSAMMENFASSUNG

- **Allgemeine Risikostufe: Hoch** — 5 Bereiche wurden untersucht; das höchste Risiko liegt im Bereich **SSL/TLS-Konfigurationsprüfung** (auf Zertifikats- und/oder Protokollebene wurde ein dringend zu behebendes Problem festgestellt.).
- ⚠️ **HTTPS wird nicht unterstützt:** Das Ziel hat über HTTPS (443) nicht geantwortet; die Kommunikation wird unverschlüsselt (im Klartext) übertragen. Die Prüfung wurde über http:// durchgeführt. Dies ist für sich genommen ein schwerwiegender Befund (siehe unten).
- **SSL/TLS-Konfigurationsprüfung:** Hoch — auf Zertifikats- und/oder Protokollebene wurde ein dringend zu behebendes Problem festgestellt.
- **Sicherheits-Header & Informationsabfluss:** Hoch — eine von außen zugängliche sensible Datei wurde festgestellt.
- **DNS- & E-Mail-Sicherheit:** Mittel — bei der E-Mail-Authentifizierung bestehen zu behebende Lücken.
- **CORS- & Cookie-Sicherheit:** Niedrig — es fiel kein auffälliges CORS-/Cookie-Problem auf.
- **CSP-Analyse (Content-Security-Policy):** Mittel — die CSP fehlt/wird nicht erzwungen.
- **Empfohlener erster Schritt:** Beginnen Sie mit dem Bereich des höchsten Risikos; für jeden Befund finden Sie Schritt-für-Schritt-Befehle im Abschnitt „KI-Lösungsvorschläge".

## GESAMTBEWERTUNG

**Risikostufe: Hoch**

Dieses Ziel antwortet nicht über HTTPS; die Kommunikation wird unverschlüsselt (im Klartext) übertragen — vorrangig sollte mit einem gültigen TLS-Zertifikat auf HTTPS umgestellt werden. Die übrigen Bereiche wurden über http:// untersucht. Das höchste Risiko wurde im Bereich **SSL/TLS-Konfigurationsprüfung** (auf Zertifikats- und/oder Protokollebene wurde ein dringend zu behebendes Problem festgestellt.) festgestellt; es wird empfohlen, dies vorrangig zu beheben. Nachfolgend wird jeder Bereich einzeln berichtet.

## FESTGESTELLTE RISIKEN

| Befund | Schweregrad | Beschreibung |
|-------|--------|----------|
| HTTPS wird nicht unterstützt (unverschlüsselte Kommunikation) | Hoch | Die Website antwortet nicht auf HTTPS; der gesamte Datenverkehr wird unverschlüsselt (im Klartext) übertragen — er kann abgehört/verändert, Sitzungen/Passwörter können gestohlen werden. Lösung: gültiges TLS-Zertifikat + HTTP→HTTPS-Weiterleitung + HSTS. |

## SSL/TLS-Konfigurationsprüfung

### TLS-ZERTIFIKATSSTATUS

⚠️ Dieses Ziel hat **über HTTPS (443) nicht geantwortet**; es wurde kein gültiges TLS-Zertifikat gefunden. Die Website ist nur über **unverschlüsseltes HTTP** erreichbar.

### TLS-PROTOKOLL & CIPHER

- **Aktives Protokoll:** nicht ermittelbar
- **Cipher:** nicht ermittelbar
- **Unterstützung veralteter/schwacher Versionen:** Nicht beobachtet (nur TLS 1.2+ gesehen)

### HSTS (HTTP Strict Transport Security)

- **Status:** Fehlt — dem Browser wird die HTTPS-Pflicht nicht mitgeteilt; bei ersten Anfragen besteht das Risiko eines SSL-Stripping-/Downgrade-Angriffs.

### FESTGESTELLTE RISIKEN

| Befund | Schweregrad | Beschreibung |
|-------|--------|----------|
| HTTPS wird nicht unterstützt (unverschlüsselte Kommunikation) | Hoch | Die Website antwortet nicht auf HTTPS; der gesamte Datenverkehr wird unverschlüsselt (im Klartext) übertragen. Ein Angreifer im selben Netzwerk kann abhören, Sitzungen/Passwörter stehlen oder Inhalte verändern. Lösung: gültiges TLS-Zertifikat + HTTP→HTTPS-Weiterleitung + HSTS. |
| HSTS fehlt | Mittel | Dem Browser wird die HTTPS-Pflicht nicht mitgeteilt; anfällig für Downgrade-Angriffe. |

## Sicherheits-Header & Informationsabfluss

### HTTP-SICHERHEITS-HEADER

| Header | Status | Beschreibung |
|--------|-------|----------|
| Strict-Transport-Security | Fehlt | HTTPS-Pflicht wird nicht mitgeteilt; SSL-Stripping-Risiko. |
| Content-Security-Policy | Fehlt | Keine browserseitige Verteidigung gegen XSS/Injektion. |
| X-Frame-Options | Fehlt | Anfällig für Clickjacking; kann in ein iframe eingebettet werden. |
| X-Content-Type-Options | Fehlt | MIME-Sniffing möglich. |
| Referrer-Policy | Fehlt | Referrer-Informationen können an externe Quellen abfließen. |
| Permissions-Policy | Fehlt | Sensible Browser-APIs sind nicht eingeschränkt. |
| X-XSS-Protection | Fehlt | Der XSS-Filter älterer Browser ist nicht gesetzt (in modernen Browsern nicht kritisch). |

### INFORMATIONSABFLUSS / OFFEN ZUGÄNGLICHE DATEIEN

Häufige sensible Pfade wurden mit einem einzelnen GET geprüft (Inhalt verifiziert — allein HTTP 200 gilt nicht als Nachweis):

| Pfad | Status | Hinweis |
|-----|-------|-----|
| `/.git/config` | Geschlossen | HTTP 400 / leerer Körper — nicht zugänglich |
| `/.env` | Geschlossen | HTTP 404 / leerer Körper — nicht zugänglich |
| `/.git/HEAD` | Geschlossen | HTTP 400 / leerer Körper — nicht zugänglich |
| `/backup.zip` | Geschlossen | HTTP 404 / leerer Körper — nicht zugänglich |
| `/.DS_Store` | Geschlossen | HTTP 404 / leerer Körper — nicht zugänglich |
| `/wp-config.php.bak` | Geschlossen | HTTP 404 / leerer Körper — nicht zugänglich |
| `/ftp` | Geschlossen | HTTP 404 / leerer Körper — nicht zugänglich |
| `/backup` | Geschlossen | HTTP 404 / leerer Körper — nicht zugänglich |
| `/backups` | Geschlossen | HTTP 404 / leerer Körper — nicht zugänglich |
| `/uploads` | Geschlossen | HTTP 404 / leerer Körper — nicht zugänglich |
| `/files` | Geschlossen | HTTP 400 / leerer Körper — nicht zugänglich |
| `/admin` | Geschlossen | HTTP 404 / leerer Körper — nicht zugänglich |
| `/.svn/entries` | Geschlossen | HTTP 400 / leerer Körper — nicht zugänglich |
| `/.htaccess` | Geschlossen | HTTP 403 / leerer Körper — nicht zugänglich |
| `/config.php.bak` | Geschlossen | HTTP 404 / leerer Körper — nicht zugänglich |
| `/db.sql` | ⚠️ OFFEN | erwartetes Dateiformat verifiziert (kein Catch-all) |
| `/dump.sql` | Geschlossen | HTTP 404 / leerer Körper — nicht zugänglich |

### FESTGESTELLTE RISIKEN

| Befund | Schweregrad | Beschreibung |
|-------|--------|----------|
| Sensible Datei zugänglich (`/db.sql`) | Hoch | Inhalt verifiziert; Risiko eines Konfigurations-/Quellcode-Abflusses. Der Zugriff sollte umgehend blockiert werden. |
| Veraltete/nicht unterstützte Softwareversion wird offengelegt (PHP/7.1.26 — EOL) | Hoch | Die PHP-7.x-Reihe wird offiziell nicht mehr unterstützt (die Sicherheitsupdates für 7.x endeten Ende 2022). Zahlreiche bekannte Schwachstellen bleiben ungepatcht. CWE-1104 · OWASP A06:2021 (Veraltete/anfällige Komponenten). Lösung: Aktualisieren Sie auf eine aktuelle und unterstützte PHP-Version (8.2+); verbergen Sie die Versionssignatur (expose_php=Off). |
| Nicht aktuelle Softwareversion wird offengelegt (Apache/2.4.25 — sehr alter Patch) | Mittel | Die Apache-2.4-Reihe wird zwar unterstützt, aber Apache/2.4.25 ist ein sehr alter Patch-Stand; die zwischenzeitlichen Sicherheitspatches scheinen nicht eingespielt worden zu sein. CWE-1104 · OWASP A06:2021 (Veraltete/anfällige Komponenten). Lösung: Aktualisieren Sie auf den aktuellen Patch der 2.4-Reihe; verbergen Sie die Versionssignatur (ServerTokens Prod). |
| Kritische Sicherheits-Header fehlen (Content-Security-Policy, X-Frame-Options) | Mittel | Schwache browserseitige Verteidigung gegen XSS/Clickjacking. (Fehlt auf 2/2 Seiten) |
| Zusätzliche Header fehlen (Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection) | Mittel | Schwache Tiefenverteidigung. (Fehlt auf 2/2 Seiten) |

## DNS- & E-Mail-Sicherheit

### SPF (Absenderrichtlinie) — geprüfte Domain: `vulnweb.com`

- **Status:** Vorhanden — `v=spf1 ~all`
- **Härte:** `~all` — weich (softfail; akzeptabel, aber nicht ideal).

### DMARC (Authentifizierungsrichtlinie) — geprüfte Domain: `vulnweb.com`

- **Status:** Fehlt — es wurde kein DMARC-Eintrag gefunden. Auf Basis der SPF/DKIM-Ergebnisse erfolgt keine Durchsetzung; der Schutz gegen Spoofing ist schwach.

### DKIM (Signatur)

- **Status:** Nicht ermittelbar — bei gängigen Selektoren (default/google/selector1…) wurde kein DKIM-Eintrag gefunden. Sie verwenden möglicherweise einen anderen Selektor; dies bedeutet kein sicheres „nicht vorhanden".

### DNSSEC

- **Status:** Passiv/nicht vorhanden — die DNS-Antworten sind nicht signiert; anfälliger für DNS-Spoofing/Cache-Poisoning.

### FESTGESTELLTE RISIKEN

| Befund | Schweregrad | Beschreibung |
|-------|--------|----------|
| DMARC fehlt | Mittel | Die SPF/DKIM-Ergebnisse werden nicht durchgesetzt. |
| DKIM nicht ermittelbar | Hinweis | Bei gängigen Selektoren nicht gefunden (kann ein anderer Selektor sein). |
| DNSSEC passiv | Hinweis | Die DNS-Antworten sind nicht signiert. |

## CORS- & Cookie-Sicherheit

### CORS-KONFIGURATION (auf 2/2 Seiten getestet)

- **Test-Origin:** `https://cybertestify-cors-probe.example` — an jede Seite wurde ein harmloser Origin-Header gesendet und die Antwort ausgewertet.
- **Offenste beobachtete Richtlinie** (`/`): Access-Control-Allow-Origin: wird nicht gesendet (geschlossen — sicherer Standard); Allow-Credentials: wird nicht gesendet.

### COOKIE-FLAGS (alle auf 2 Seiten beobachteten Cookies)

- Auf keiner der 2 geprüften Seiten wurde ein Set-Cookie beobachtet.

### FESTGESTELLTE RISIKEN

- Bei der CORS- und Cookie-Konfiguration fiel kein auffälliges Risiko auf.

## CSP-Analyse (Content-Security-Policy)

### CSP-STATUS

- **Status:** Fehlt — der Content-Security-Policy-Header wird überhaupt nicht gesendet.

### CSP-DIREKTIVENANALYSE

- Da keine CSP angewendet wird, konnte keine Direktivenanalyse durchgeführt werden.

### FESTGESTELLTE RISIKEN

| Befund | Schweregrad | Beschreibung |
|-------|--------|----------|
| CSP vollständig fehlt | Mittel | Keine browserseitige Verteidigung gegen XSS und Content-Injektion. Auf ALLEN 2 geprüften Seiten fehlt der CSP-Header. |

## POSITIVE ZUSICHERUNG — GEPRÜFTE BEREICHE

Einschließlich der Bereiche ohne Befund wurden die Prüfungen der externen Angriffsfläche auf **2 eindeutigen Seiten** einschließlich der Startseite tatsächlich ausgeführt. Die folgende Tabelle zeigt transparent auch die Ergebnisse „kein Problem gefunden":

| Prüfbereich | Ergebnis |
|---------------|-------|
| SSL/TLS-Konfigurationsprüfung | ⚠️ Befund vorhanden (Hoch — oben ausführlich) |
| Sicherheits-Header & Informationsabfluss | ⚠️ Befund vorhanden (Hoch — oben ausführlich) |
| DNS- & E-Mail-Sicherheit | ⚠️ Befund vorhanden (Mittel — oben ausführlich) |
| CORS- & Cookie-Sicherheit | ✅ Kein Problem gefunden |
| CSP-Analyse (Content-Security-Policy) | ⚠️ Befund vorhanden (Mittel — oben ausführlich) |

> **Drei-Zustands-Unterscheidung (Ehrlichkeit):** ✅ *Kein Problem gefunden* = Prüfung lief, sauberes Ergebnis · ⚠️ *Befund vorhanden* = oben ausführlich · ⚠️ *Nicht überprüfbar* = keine Daten erhoben (bedeutet NICHT sicher).

### Was dieses Paket prüft und was NICHT

**PRÜFT (passiv — nur Seitenabruf per GET + harmlose Origin-/DNS-Abfrage):** TLS/Zertifikat, HTTP-Sicherheits-Header, CORS-Richtlinie, Cookie-Flags (Secure/HttpOnly/SameSite), Content-Security-Policy, DNS-/E-Mail-Einträge (SPF/DKIM/DMARC/DNSSEC), offen zugängliche sensible Dateien, veraltete/nicht unterstützte Softwareversionen — auf den 2 entdeckten Seiten.

**PRÜFT NICHT:** Aktive Schwachstellenverifikation (Payload-/Sondenversuche wie SQLi/XSS/IDOR), Test authentifizierter Abläufe, Ausnutzung von Geschäftslogik. Diese fallen in den Umfang der Pakete **Aktive Verifikation** und **Umfassender Pentest**. Dieser Bericht beruht auf passiver Beobachtung; die Aussage „kein Befund" in einem Bereich **BEWEIST NICHT**, dass er sicher ist, da kein aktiver Angriff versucht wurde — sie zeigt lediglich, dass die von außen beobachtete Konfiguration sauber ist.
