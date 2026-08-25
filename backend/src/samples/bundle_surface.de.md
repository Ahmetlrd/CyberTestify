## MANAGEMENTZUSAMMENFASSUNG

- **Gesamtrisikostufe: Hoch** — 5 Bereiche wurden geprüft; das höchste Risiko liegt im Bereich **SSL/TLS-Konfigurationsaudit** (auf Zertifikats- und/oder Protokollebene wurde ein dringend zu behebendes Problem festgestellt.).
- ⚠️ **HTTPS wird nicht unterstützt:** Das Ziel hat nicht über HTTPS (443) geantwortet; die Kommunikation läuft unverschlüsselt (Klartext). Die Prüfung wurde über http:// durchgeführt. Das ist für sich genommen ein ernster Befund (siehe unten).
- **SSL/TLS-Konfigurationsaudit:** Hoch — auf Zertifikats- und/oder Protokollebene wurde ein dringend zu behebendes Problem festgestellt.
- **Sicherheits-Header & Informationslecks:** Hoch — eine von außen erreichbare sensible Datei wurde festgestellt.
- **DNS- & E-Mail-Sicherheit:** Mittel — bei der E-Mail-Authentifizierung bestehen zu behebende Lücken.
- **CORS- & Cookie-Sicherheit:** Niedrig — es wurde kein deutliches CORS-/Cookie-Problem festgestellt.
- **CSP-Analyse (Content Security Policy):** Mittel — CSP fehlt/wird nicht durchgesetzt.
- **Empfohlener erster Schritt:** Beginnen Sie mit dem Bereich mit dem höchsten Risiko; für jeden Befund werden schrittweise fertige Befehle im Abschnitt „KI-Lösungsvorschläge" bereitgestellt.

## GESAMTBEWERTUNG

**Risikostufe: Hoch**

Dieses Ziel antwortet nicht über HTTPS; die Kommunikation läuft unverschlüsselt (Klartext) — vorrangig sollte mit einem gültigen TLS-Zertifikat auf HTTPS umgestellt werden. Die übrigen Bereiche wurden über http:// geprüft. Das höchste Risiko wurde im Bereich **SSL/TLS-Konfigurationsaudit** (auf Zertifikats- und/oder Protokollebene wurde ein dringend zu behebendes Problem festgestellt.) festgestellt; eine vorrangige Behebung wird empfohlen. Nachfolgend wird jeder Bereich einzeln berichtet.

## FESTGESTELLTE RISIKEN

| Befund | Schweregrad | Beschreibung |
|-------|--------|----------|
| HTTPS wird nicht unterstützt (unverschlüsselte Kommunikation) | Hoch | Die Website antwortet nicht über HTTPS; der gesamte Verkehr wird unverschlüsselt (Klartext) übertragen — mitlesbar/veränderbar, Sitzungen/Passwörter können gestohlen werden. Lösung: gültiges TLS-Zertifikat + HTTP→HTTPS-Umleitung + HSTS. |

## SSL/TLS-Konfigurationsaudit

### TLS-ZERTIFIKATSSTATUS

⚠️ Dieses Ziel **hat nicht über HTTPS (443) geantwortet**; es wurde kein gültiges TLS-Zertifikat gefunden. Die Website ist nur über **unverschlüsseltes HTTP** erreichbar.

### TLS-PROTOKOLL & CIPHER

- **Aktives Protokoll:** nicht ermittelbar
- **Cipher:** nicht ermittelbar
- **Unterstützung veralteter/schwacher Versionen:** Nicht beobachtet (nur TLS 1.2+ gesehen)

### HSTS (HTTP Strict Transport Security)

- **Status:** Fehlt — Dem Browser wird die HTTPS-Pflicht nicht mitgeteilt; bei Erstanfragen besteht das Risiko von SSL-Stripping-/Downgrade-Angriffen.

### FESTGESTELLTE RISIKEN

| Befund | Schweregrad | Beschreibung |
|-------|--------|----------|
| HTTPS wird nicht unterstützt (unverschlüsselte Kommunikation) | Hoch | Die Website antwortet nicht über HTTPS; der gesamte Datenverkehr wird unverschlüsselt (Klartext) übertragen. Ein Angreifer im selben Netzwerk kann mithören, Sitzungen/Passwörter stehlen oder Inhalte verändern. Lösung: gültiges TLS-Zertifikat + HTTP→HTTPS-Umleitung + HSTS. |
| HSTS fehlt | Mittel | Die HTTPS-Pflicht wird dem Browser nicht mitgeteilt; anfällig für Downgrade-Angriffe. |

## Sicherheits-Header & Informationslecks

### HTTP-SICHERHEITS-HEADER

| Header | Status | Beschreibung |
|--------|-------|----------|
| Strict-Transport-Security | Fehlt | Die HTTPS-Pflicht wird nicht mitgeteilt; SSL-Stripping-Risiko. |
| Content-Security-Policy | Fehlt | Keine Browser-Verteidigung gegen XSS/Injection. |
| X-Frame-Options | Fehlt | Anfällig für Clickjacking; kann in ein iframe eingebettet werden. |
| X-Content-Type-Options | Fehlt | MIME-Sniffing möglich. |
| Referrer-Policy | Fehlt | Referrer-Informationen können an externe Quellen abfließen. |
| Permissions-Policy | Fehlt | Sensible Browser-APIs sind nicht eingeschränkt. |
| X-XSS-Protection | Fehlt | Der Legacy-XSS-Filter älterer Browser ist nicht gesetzt (in modernen Browsern unkritisch). |

### INFORMATIONSLECKS / OFFENLIEGENDE DATEIEN

Häufige sensible Pfade wurden mit einem einzigen GET geprüft (Inhalt verifiziert — allein HTTP 200 gilt nicht als Nachweis):

| Pfad | Status | Hinweis |
|-----|-------|-----|
| `/.git/config` | Geschlossen | HTTP 400 / leerer Body — nicht erreichbar |
| `/.env` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/.git/HEAD` | Geschlossen | HTTP 400 / leerer Body — nicht erreichbar |
| `/backup.zip` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/.DS_Store` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/wp-config.php.bak` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/ftp` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/backup` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/backups` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/uploads` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/files` | Geschlossen | HTTP 400 / leerer Body — nicht erreichbar |
| `/admin` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/.svn/entries` | Geschlossen | HTTP 400 / leerer Body — nicht erreichbar |
| `/.htaccess` | Geschlossen | HTTP 403 / leerer Body — nicht erreichbar |
| `/config.php.bak` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/db.sql` | ⚠️ OFFEN | erwartetes Dateiformat bestätigt (kein Catch-all) |
| `/dump.sql` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/backup.tar.gz` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/backup.tar` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/www.zip` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/site.zip` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/backup.old` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/backup.backup` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/index.php.bak` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/index.php~` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/.env.bak` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/.env.old` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |
| `/database.sql` | Geschlossen | HTTP 404 / leerer Body — nicht erreichbar |

### ZUSÄTZLICHE INFORMATIONSLECK-BEOBACHTUNGEN

| Prüfung | Ergebnis |
|-----|-------|
| Verzeichnisauflistung (autoindex / „Index of /") · CWE-548 | ✅ 6 Verzeichnisse geprüft, keine Auflistung |
| Ausführlicher Fehler / Serverpfad-Offenlegung · CWE-209 | ✅ Kein Indikator gefunden |
| autocomplete-Richtlinie im Passwortfeld · CWE-522 | ✅ Angemessen / kein Passwortfeld beobachtet |

> Alles GET-only/passive Beobachtung — Inhalte werden NICHT abgerufen/angezeigt; ein geleakter Pfad wird REDIGIERT. „Kein Indikator gefunden" BEWEIST NICHT, dass es sicher ist; es zeigt nur, dass mit den passiven Methoden kein Indikator auftrat.

### FESTGESTELLTE RISIKEN

| Befund | Schweregrad | Beschreibung |
|-------|--------|----------|
| Sensible Datei erreichbar (`/db.sql`) | Hoch | Inhalt verifiziert; Risiko eines Konfigurations-/Quellcode-Lecks. Der Zugriff muss umgehend gesperrt werden. |
| Veraltete/nicht mehr unterstützte Softwareversion wird offengelegt (PHP/7.1.26 — EOL) | Hoch | Die PHP-7.x-Serie wird offiziell nicht mehr unterstützt (Sicherheitsupdates für 7.x endeten Ende 2022). Zahlreiche bekannte Sicherheitslücken bleiben ungepatcht. CWE-1104 · OWASP A06:2021 (Veraltete/Verwundbare Komponenten). Lösung: Auf eine aktuelle, unterstützte PHP-Version (8.2+) aktualisieren; die Versionssignatur verbergen (expose_php=Off). |
| Nicht aktuelle Softwareversion wird offengelegt (Apache/2.4.25 — sehr alter Patchstand) | Mittel | Die Apache-2.4-Serie wird zwar unterstützt, Apache/2.4.25 ist jedoch ein sehr alter Patchstand; zwischenzeitliche Sicherheitspatches scheinen nicht eingespielt zu sein. CWE-1104 · OWASP A06:2021 (Veraltete/Verwundbare Komponenten). Lösung: Auf den aktuellen Patch der 2.4-Serie aktualisieren; die Versionssignatur verbergen (ServerTokens Prod). |
| Kritische Sicherheits-Header fehlen (Content-Security-Policy, X-Frame-Options) | Mittel | Die Browser-Verteidigung gegen XSS/Clickjacking ist schwach. (fehlt auf 2/2 Seiten) |
| Weitere Header fehlen (Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection) | Mittel | Die Verteidigungstiefe ist schwach. (fehlt auf 2/2 Seiten) |

## DNS- & E-Mail-Sicherheit

### SPF (Sender-Richtlinie) — geprüfte Domain: `vulnweb.com`

- **Status:** Vorhanden — `v=spf1 ~all`
- **Härte:** `~all` — weich (softfail; akzeptabel, nicht ideal).

### DMARC (Authentifizierungsrichtlinie) — geprüfte Domain: `vulnweb.com`

- **Status:** Fehlt — Es wurde kein DMARC-Eintrag gefunden. Es erfolgt keine Durchsetzung anhand der SPF/DKIM-Ergebnisse; der Schutz vor Spoofing ist schwach.

### DKIM (Signatur)

- **Status:** Nicht erkannt — Bei gängigen Selektoren (default/google/selector1…) wurde kein DKIM-Eintrag gefunden. Möglicherweise verwenden Sie einen anderen Selektor; dies bedeutet nicht sicher „kein Eintrag".

### DNSSEC

- **Status:** Passiv/fehlt — DNS-Antworten sind nicht signiert; erhöhtes Risiko für DNS-Spoofing/Cache-Poisoning.

### FESTGESTELLTE RISIKEN

| Befund | Schweregrad | Beschreibung |
|-------|--------|----------|
| DMARC fehlt | Mittel | Die SPF/DKIM-Ergebnisse werden nicht durchgesetzt. |
| DKIM nicht erkannt | Hinweis | Bei gängigen Selektoren nicht gefunden (möglicherweise anderer Selektor). |
| DNSSEC passiv | Hinweis | Die DNS-Antworten sind nicht signiert. |

## CORS- & Cookie-Sicherheit

### CORS-KONFIGURATION (auf 2/2 Seiten getestet)

- **Test-Origin:** `https://cybertestify-cors-probe.example` — an jede Seite wurde ein harmloser Origin-Header gesendet und die Antwort ausgewertet.
- **Offenste beobachtete Richtlinie** (`/`): Access-Control-Allow-Origin: wird nicht gesendet (geschlossen — sichere Voreinstellung); Allow-Credentials: wird nicht gesendet.

### COOKIE-FLAGS (alle auf 2 Seiten beobachteten Cookies)

- Auf keiner der 2 geprüften Seiten wurde ein Set-Cookie beobachtet.

### FESTGESTELLTE RISIKEN

- Bei der CORS- und Cookie-Konfiguration wurde kein deutliches Risiko festgestellt.

## CSP-Analyse (Content Security Policy)

### CSP-STATUS

- **Status:** Fehlt — Es wird kein Content-Security-Policy-Header gesendet.

### CSP-DIREKTIVENANALYSE

- Da keine durchgesetzte CSP vorhanden ist, konnte keine Direktivenanalyse durchgeführt werden.

### FESTGESTELLTE RISIKEN

| Befund | Schweregrad | Beschreibung |
|-------|--------|----------|
| CSP vollständig fehlend | Mittel | Keine Verteidigung auf Browser-Ebene gegen XSS und Content-Injection. Auf ALLEN 2 geprüften Seiten fehlt der CSP-Header. |

## POSITIVE ZUSICHERUNG — GEPRÜFTE BEREICHE

Auch die Bereiche ohne Befund eingeschlossen, wurden die Kontrollen der externen Angriffsfläche tatsächlich auf **2 einzigartigen Seiten** einschließlich der Startseite ausgeführt. Die folgende Tabelle zeigt auch die „kein Problem gefunden"-Ergebnisse transparent:

| Kontrollbereich | Ergebnis |
|---------------|-------|
| SSL/TLS-Konfigurationsaudit | ⚠️ Befund vorhanden (Hoch — oben im Detail) |
| Sicherheits-Header & Informationslecks | ⚠️ Befund vorhanden (Hoch — oben im Detail) |
| DNS- & E-Mail-Sicherheit | ⚠️ Befund vorhanden (Mittel — oben im Detail) |
| CORS- & Cookie-Sicherheit | ✅ Kein Problem gefunden |
| CSP-Analyse (Content Security Policy) | ⚠️ Befund vorhanden (Mittel — oben im Detail) |

> **Drei-Zustands-Unterscheidung (Ehrlichkeit):** ✅ *Kein Problem gefunden* = Kontrolle lief, Ergebnis sauber · ⚠️ *Befund vorhanden* = oben im Detail · ⚠️ *Nicht prüfbar* = keine Daten erhebbar (bedeutet NICHT sicher).

### Was dieses Paket prüft — und was NICHT

**PRÜFT (passiv — nur Seitenabruf per GET + harmlose Origin-/DNS-Abfrage):** TLS/Zertifikat, HTTP-Sicherheits-Header, CORS-Richtlinie, Cookie-Flags (Secure/HttpOnly/SameSite), Content-Security-Policy, DNS-/E-Mail-Einträge (SPF/DKIM/DMARC/DNSSEC), offenliegende sensible Dateien (inkl. gängiger Backup-Muster), Verzeichnisauflistung (autoindex), ausführliche-Fehler-/Serverpfad-Offenlegung (redigiert), autocomplete-Richtlinie im Passwortfeld, veraltete/nicht unterstützte Softwareversionen — auf den 2 entdeckten Seiten.

**PRÜFT NICHT:** Aktive Schwachstellenverifikation (Payload-/Probe-Versuche wie SQLi/XSS/IDOR), authentifizierte Ablauftests, Missbrauch der Geschäftslogik. Diese gehören zum Umfang der Pakete **Aktive Verifikation** und **Umfassender Pentest**. Dieser Bericht beruht auf passiver Beobachtung; die Aussage „kein Befund" in einem Bereich **BEWEIST NICHT**, dass er sicher ist, da kein aktiver Exploit versucht wurde — sie zeigt lediglich, dass die von außen beobachtete Konfiguration sauber ist.

