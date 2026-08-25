## MANAGEMENTZUSAMMENFASSUNG

- **Gesamtrisikostufe: Hoch** — 3 Bereiche untersucht; das höchste Risiko liegt im Bereich **CMS- & bekannte-CVE-Prüfung** (Kein bekannter CMS-Fingerabdruck festgestellt · 21 bekannte CVE in der Server-/Software-Version).
- ⚠️ **HTTPS wird nicht unterstützt:** Das Ziel hat nicht über HTTPS (443) geantwortet; die Erkundung wurde über http:// durchgeführt. Unverschlüsselte Kommunikation ist für sich genommen ein ernster Befund (siehe unten).
- **Subdomain-Takeover-Prüfung:** Niedrig — In den Certificate-Transparency-Einträgen wurde keine Subdomain gesehen
- **API- & Swagger-Erkundung:** Niedrig — Keine öffentlich zugängliche API-/Swagger-Dokumentation gefunden
- **CMS- & bekannte-CVE-Prüfung:** Hoch — Kein bekannter CMS-Fingerabdruck festgestellt · 21 bekannte CVE in der Server-/Software-Version
- **Umfang (echte Zahlen):** 0 Subdomains inventarisiert · 12 API-/Swagger-Pfade geprüft (2 Seiten gescannt) · 6+ passive CMS-/Technologiesignale untersucht.
- **Empfohlener erster Schritt:** Beginnen Sie mit dem Bereich mit dem höchsten Risiko; für jeden Befund werden schrittweise fertige Lösungen im Abschnitt „KI-Lösungsvorschläge" bereitgestellt.

## GESAMTBEWERTUNG

**Risikostufe: Hoch**

Dieses Ziel antwortet nicht über HTTPS; die Kommunikation wird unverschlüsselt übertragen (vorrangig sollte auf HTTPS umgestellt werden). Das höchste Risiko wurde im Bereich **CMS- & bekannte-CVE-Prüfung** (Kein bekannter CMS-Fingerabdruck festgestellt · 21 bekannte CVE in der Server-/Software-Version) festgestellt; eine vorrangige Behebung wird empfohlen. Nachfolgend wird jeder Bereich einzeln berichtet.

## FESTGESTELLTE RISIKEN

| Befund | Schweregrad | Beschreibung |
|-------|--------|----------|
| HTTPS wird nicht unterstützt (unverschlüsselte Kommunikation) | Hoch | Das Ziel antwortet nicht über HTTPS; der gesamte Verkehr wird unverschlüsselt (Klartext) übertragen — mitlesbar/veränderbar. Lösung: gültiges TLS-Zertifikat + HTTP→HTTPS-Umleitung + HSTS. |
| CMS- & bekannte-CVE-Prüfung — Kein bekannter CMS-Fingerabdruck festgestellt · 21 bekannte CVE in der Server-/Software-Version | Hoch | Details im Abschnitt „CMS- & bekannte-CVE-Prüfung" unten. |

## UMFANG UND METHODIK

Dieser Bericht wurde in drei Erkundungsbereichen mit **passiven** (nicht ausnutzenden) Techniken automatisch aus von außen beobachtbaren Daten erzeugt:

- **Subdomain-Takeover:** Subdomains werden aus Certificate-Transparency-Logs (crt.sh, ersatzweise certSpotter) erhoben; jede wird per Cloudflare DoH einer DNS-/CNAME-Auflösung unterzogen und mit einer Signaturdatenbank bekannter „dangling" (verlassener Cloud-Dienste) verglichen.
- **API- & Swagger-Erkundung:** Eine feste Liste gängiger API-Dokumentationspfade wird per GET geprüft; gefundene OpenAPI/Swagger-Schemata werden geparst und sensible/nicht authentifizierte Endpunkte markiert (die Endpunkte werden nicht aufgerufen).
- **CMS & bekannte CVE:** Über HTTP-Header, `<meta generator>` und HTML-Muster werden CMS- und Versions-Fingerabdruck ermittelt; ist der Generator verborgen, wird über die EXISTENZ bekannter CMS-Pfade (nur GET/Existenz — kein Login-Versuch) verifiziert. Die erkannte Version wird durch Abfrage der NVD (NIST National Vulnerability Database) mit bekannten CVEs abgeglichen, die die Version ausdrücklich abdecken; ist die Version nicht lesbar, erfolgt keine CVE-Zuordnung (keine erfundenen CVEs).

> Alle Daten wurden von außen und ohne Schaden am Ziel erhoben. Authentifizierungspflichtige Bereiche, das interne Netzwerk und aktive Ausnutzung liegen außerhalb des Umfangs dieses Pakets.

## Subdomain-Takeover-Prüfung

**Gesamtrisikostufe: Niedrig — In den Certificate-Transparency-Einträgen wurde keine Subdomain gesehen**

Aus den Certificate-Transparency-Einträgen (crt.sh / certSpotter) wurden **0** eindeutige Subdomains inventarisiert; davon wurde bei **0** der CNAME-Eintrag aufgelöst und auf Übernahme (Subdomain-Takeover) untersucht.

In den aufgelösten CNAME-Einträgen wurde keine **übernehmbare (dangling)** Subdomain festgestellt, die auf eine verlassene Cloud-Ressource zeigt. Das zeigt, dass Ihre von außen sichtbare Subdomain-Fläche derzeit **schmal und kontrolliert** wirkt.

> Umfang: Nur passive Quellen (Certificate-Transparency-Logs + beobachtbares DNS). Es wurde kein Subdomain-Brute-Force / aktiver Scan durchgeführt.

## API- & Swagger-Erkundung

**Gesamtrisikostufe: Niedrig — Keine öffentlich zugängliche API-/Swagger-Dokumentation gefunden**

Die folgenden **12** gängigen API-Dokumentations-/Erkundungspfade wurden per GET geprüft. Kein Endpunkt wurde aufgerufen/ausgenutzt (passive Erkundung).

### Geprüfte Pfade (vollständige Liste)

| Pfad | HTTP | Status |
|-----|------|-------|
| /openapi.json | 404 | Nicht gefunden |
| /swagger.json | 404 | Nicht gefunden |
| /v2/api-docs | 400 | Nicht gefunden |
| /v3/api-docs | 400 | Nicht gefunden |
| /api-docs | 404 | Nicht gefunden |
| /api/docs | 400 | Nicht gefunden |
| /api/v1/docs | 400 | Nicht gefunden |
| /swagger-ui.html | 404 | Nicht gefunden |
| /swagger/index.html | 400 | Nicht gefunden |
| /redoc | 404 | Nicht gefunden |
| /.well-known/openapi.json | 400 | Nicht gefunden |
| /graphql | 404 | Nicht gefunden |

Keiner der geprüften Pfade lieferte ein öffentlich zugängliches API-Schema/-Interface. Das Fehlen öffentlicher API-Dokumentation bedeutet, dass Angreifer Ihre API-Fläche von außen nicht leicht **kartieren** können — das ist im Hinblick auf die externe Angriffsfläche ein positives Zeichen.

> Umfang: Nur öffentlich zugängliche Dokumentationspfade wurden per GET geprüft; kein Endpunkt wurde aufgerufen/ausgenutzt (passive Erkundung).

## CMS- & bekannte-CVE-Prüfung

**Gesamtrisikostufe: Hoch — Kein bekannter CMS-Fingerabdruck festgestellt · 21 bekannte CVE in der Server-/Software-Version**

### Untersuchte Fingerabdruck-Quellen

Zur CMS-/Framework- und Versionserkennung wurden in der Startseiten-Antwort die folgenden passiven Signale betrachtet:

- HTTP-Antwort-Header (`Server`, `X-Powered-By`, `X-Generator`, `X-Drupal-Cache`, `X-Magento-Cache-Debug`)
- `<meta name="generator">`-Tag
- HTML-Pfad-/Musterspuren (`/wp-content/`, `/wp-includes/`, `Drupal.settings`, `/sites/all/`, `option=com_`, `/media/jui/`, `typo3conf`, `Magento_`)
- Gängige Versionsdateien (WordPress `/readme.html`, Drupal `/CHANGELOG.txt`)
- EXISTENZ bekannter CMS-Pfade (`/wp-login.php`, `/wp-json/`, `/administrator/`, `/user/login`, `/typo3/` — nur Vorhanden/Nicht-Vorhanden-Prüfung; KEIN Login-/Passwortversuch)
- Bibliotheks-/Plugin-Hinweise (WooCommerce, jQuery-Version)

**Keines** dieser Signale stimmte mit einem bekannten CMS/Framework überein. Das deutet auf eine eigenentwickelte Anwendung oder eine Installation hin, die CMS-Spuren bewusst verbirgt; beides erschwert die automatische CMS-/CVE-Zuordnung von außen.

### Server-/Software-Banner-Version — Bekannte CVE (NVD)

Die aus dem Banner ermittelte(n) Version(en) wurden mit der NVD abgeglichen (KEINE Ausnutzung/Verifikation — nur der Indikator „gibt es bekannte CVEs für diese Version"):

| Software/Version | NVD-Ergebnis | Beispiel-CVE |
|-----|-------|-------|
| Apache httpd 2.4.25 | nicht abfragbar (NICHT sauber) | — |
| PHP 7.1.26 | ⚠️ 21 bekannte CVE | [CVE-2017-8923](https://nvd.nist.gov/vuln/detail/CVE-2017-8923) |

> **Hinweis:** Die folgende CVE-Liste enthält bekannte Schwachstellen, die anhand der erkannten Version **automatisch über die NVD (NIST National Vulnerability Database) zugeordnet** wurden; ob sie für Ihre Version ausnutzbar sind, ist **nicht verifiziert**, und ein Teil kann von Plugins/Themes stammen. Für eine gesicherte Einschätzung werden ein Update + eine gezielte Verifikation empfohlen.

> Umfang: Passiver Fingerabdruck + CVE-Zuordnung über die NVD. Keine CVE wurde **ausgenutzt/verifiziert**.

## POSITIVE ZUSICHERUNG — GEPRÜFTE ERKUNDUNGSMETHODEN

Die Erkundung fällt bei den meisten gesunden Zielen sauber aus; dieser Abschnitt macht auch das Ergebnis „nichts gefunden" TRANSPARENT — er zeigt, was TATSÄCHLICH geprüft wurde (inklusive **2 Seiten** Sitemap, Startseite eingeschlossen):

| Erkundungsbereich | Ergebnis |
|-------------|-------|
| Subdomain-Takeover-Prüfung | ✅ 0 Subdomain-Einträge geprüft; kein Übernahme-Indikator gefunden |
| API- & Swagger-Erkundung | ✅ 12 Pfade geprüft (12 fest + 0 Sitemap-Kandidaten, aus 2 Seiten); kein öffentlich zugängliches API-Schema gefunden |
| CMS-/Framework-CVE-Abgleich | ✅ Kein bekannter CMS-/Framework-Fingerabdruck festgestellt |

> **Drei-Zustands-Unterscheidung (Ehrlichkeit):** ✅ *Kein Indikator gefunden* = Methode lief, sauber · ⚠️ *Indikator vorhanden* = oben im Detail · ⚠️ *Nicht prüfbar* = keine Daten erhebbar (bedeutet NICHT sicher).

### Was dieses Paket bewertet — und was NICHT

**BEWERTET (passive Erkundung — nur GET, externe Quellen):** Subdomain-Inventar + Übernahme (dangling CNAME), öffentlich zugängliches API-/Swagger-/OpenAPI-Dokument, CMS-/Framework- und Server-/Software-Banner-Fingerabdruck (Apache/nginx/PHP) + bekannte CVE-Übereinstimmung (NVD), EXISTENZ-Feststellung aus Sitemap + robots.txt-Disallow abgeleiteter API-/administrativ wirkender Pfade — über 2 Seiten.

**BEWERTET NICHT:** aktive Injektions-/IDOR-/XSS-Verifikation und Berechtigungsprüfung entdeckter Endpunkte (Umfang **Aktive Verifikation / Umfassender Pentest**), HTTP-Sicherheits-Header-/CORS-/Cookie-/CSP-Details (Umfang **Basis-Scan / Externe Angriffsfläche**), DSGVO/PCI/ISO-Rahmenzuordnung (Umfang **Compliance**). Die Aussage „kein Indikator gefunden" in einem Bereich **BEWEIST NICHT**, dass Sie sicher sind — sie zeigt nur, dass mit den geprüften passiven Methoden kein Indikator auftrat.

## BEST PRACTICES / EMPFOHLENE NÄCHSTE SCHRITTE

Unabhängig vom Ergebnis dieser Prüfung empfohlene dauerhafte Praktiken, um Ihre Angriffsfläche schmal zu halten:

- **Bereinigen Sie ungenutzte CNAME-Einträge regelmäßig** — Einträge, die auf verlassene Cloud-Ressourcen zeigen, bergen Subdomain-Takeover-Risiko; entfernen Sie den DNS-Eintrag, bevor Sie die Cloud-Ressource löschen.
- **Falls Sie eine API-Dokumentation (Swagger/OpenAPI) haben,** halten Sie sie nur für authentifizierten Zugriff offen; veröffentlichen Sie sie in der Produktion nicht öffentlich.
- **Halten Sie Ihre CMS-, Plugin- und Theme-Versionen** per Auto-Update oder regelmäßiger Verfolgung aktuell; bleiben Sie gegen bekannte CVEs gepatcht.
- **Erkennen Sie neue/unerwartete Subdomain-Zertifikate frühzeitig** mit Certificate-Transparency-(CT-)Log-Überwachungstools (crt.sh, certSpotter usw.).
- **Reduzieren Sie die Versions-/Technologieoffenlegung** — verraten Sie über Header/Tags wie `Server`, `X-Powered-By`, `<meta generator>` keine unnötigen Versionsinformationen.
- **Dokumentieren Sie Ihr Subdomain-Inventar** — zu wissen, welche Subdomain zu welchem Dienst/Team gehört, hilft Ihnen, brachliegende Einträge schnell zu erkennen.
