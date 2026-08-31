## MANAGEMENTZUSAMMENFASSUNG

- **Allgemeine Risikostufe: Hoch** — die Website unterstützt kein HTTPS; die Kommunikation wird unverschlüsselt (im Klartext) übertragen — sie kann abgehört/verändert werden. Vorrangig sollte auf HTTPS umgestellt werden.
- ⚠️ Dieses Ziel hat über HTTPS (443) nicht geantwortet; die Prüfung wurde **über http://** durchgeführt. Das Fehlen von HTTPS ist für sich genommen ein Befund (siehe unten).
- 6/6 wichtige Sicherheits-Header fehlen: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy, Permissions-Policy.
- **Umfang:** Die Prüfungen der Sicherheits-Header und der Versionssignatur wurden auf **8 eindeutigen Seiten** einschließlich der Startseite durchgeführt (nicht nur auf einer einzigen Seite).
- **Empfohlener erster Schritt:** Installieren Sie ein gültiges TLS-Zertifikat und verlagern Sie den gesamten Datenverkehr auf HTTPS; Schritt-für-Schritt-Befehle finden Sie in der Erweiterung „KI-Lösungsvorschläge".

> **Umfang und Grenzen:** Dieses Paket ist eine **passive, GET-basierte** externe Beobachtung; es wurde kein aktiver Angriff und keine aktive Sonde versucht. Die Aussage „kein Befund" in einem Bereich **BEWEIST NICHT**, dass er sicher ist, da kein aktiver Test durchgeführt wurde — sie zeigt lediglich, dass die von außen beobachtete Konfiguration sauber ist.

## GESAMTBEWERTUNG

**Risikostufe: Hoch**

Dieses Ziel antwortet nicht über HTTPS; die Kommunikation läuft unverschlüsselt (im Klartext) über HTTP. Dies ist ein schwerwiegender Mangel, der es einem Angreifer im selben Netzwerk ermöglicht, den Datenverkehr abzuhören/zu verändern und Sitzungen/Passwörter zu stehlen; moderne Browser kennzeichnen die Website als „Nicht sicher". Priorität hat der Umstieg auf HTTPS mit einem gültigen TLS-Zertifikat sowie das Hinzufügen einer HTTP→HTTPS-Weiterleitung + HSTS. Die übrigen Header-Prüfungen wurden über http:// durchgeführt.

## HTTP-SICHERHEITS-HEADER

| Header | Status | Beschreibung |
|--------|-------|----------|
| Strict-Transport-Security | Fehlt | Dem Browser wird die HTTPS-Pflicht nicht mitgeteilt; bei ersten Anfragen besteht das Risiko von SSL-Stripping/MITM. |
| Content-Security-Policy | Fehlt | Der Browser kann nicht einschränken, welche Ressourcen geladen werden; es gibt keine grundlegende Verteidigung gegen XSS und Content-Injektion. |
| X-Frame-Options | Fehlt | Die Seite kann in ein iframe einer anderen Website eingebettet werden; der Nutzer kann per Clickjacking getäuscht werden. |
| X-Content-Type-Options | Fehlt | Der Browser kann den Inhaltstyp erraten (MIME-Sniffing); hochgeladene Dateien könnten wie Skripte ausgeführt werden. |
| Referrer-Policy | Fehlt | An externe Links wird die vollständige URL (Referer) gesendet; Sitzungs-/Datenschutzinformationen können abfließen. |
| Permissions-Policy | Fehlt | Sensible APIs wie Kamera/Mikrofon/Standort sind nicht eingeschränkt; Drittanbieter-Inhalte könnten sie missbrauchen. |
| X-XSS-Protection | Fehlt | Der XSS-Filter älterer Browser ist nicht gesetzt (in modernen Browsern nicht kritisch; der eigentliche Schutz ist die CSP). |
| Content-Type | Vorhanden | text/html |

## TLS-ZERTIFIKATSSTATUS

⚠️ Dieses Ziel hat **über HTTPS (443) nicht geantwortet**; es wurde kein gültiges TLS-Zertifikat gefunden. Die Website ist nur über **unverschlüsseltes HTTP** erreichbar (siehe Festgestellte Risiken → „HTTPS wird nicht unterstützt"). Die folgenden Header-Prüfungen wurden über http:// durchgeführt.

## SERVER-/TECHNOLOGIESIGNATUR

- Server: Microsoft-IIS/8.5
- X-Powered-By: ASP.NET

## FESTGESTELLTE RISIKEN

| Befund | Schweregrad | Beschreibung |
|-------|--------|----------|
| HTTPS wird nicht unterstützt (unverschlüsselte Kommunikation) | Hoch | Die Website antwortet nicht auf HTTPS; der gesamte ein- und ausgehende Datenverkehr wird unverschlüsselt (im Klartext) übertragen — ein Angreifer im selben Netzwerk kann den Verkehr abhören, Sitzungen/Passwörter stehlen oder Inhalte verändern. Die Prüfung wurde über http:// durchgeführt. |
| Kritischer Sicherheits-Header fehlt: Content-Security-Policy | Mittel | Der Browser kann nicht einschränken, welche Ressourcen geladen werden; keine grundlegende Verteidigung gegen XSS und Content-Injection. Fehlt auf ALLEN 8 geprüften einzigartigen Seiten. |
| Kritischer Sicherheits-Header fehlt: X-Frame-Options | Mittel | Die Seite kann in das iframe einer fremden Website eingebettet werden; Nutzer können per Clickjacking getäuscht werden. Fehlt auf ALLEN 8 geprüften einzigartigen Seiten. |
| Sicherheits-Header fehlt: X-Content-Type-Options | Mittel | Der Browser kann den Inhaltstyp erraten (MIME-Sniffing); hochgeladene Dateien könnten wie Skripte ausgeführt werden. Fehlt auf ALLEN 8 geprüften einzigartigen Seiten. |
| Sicherheits-Header fehlt: Strict-Transport-Security | Mittel | Die HTTPS-Pflicht wird dem Browser nicht mitgeteilt; bei Erstanfragen besteht SSL-Stripping-/MITM-Risiko. Fehlt auf ALLEN 8 geprüften einzigartigen Seiten. |
| Sicherheits-Header fehlt: Referrer-Policy | Mittel | An externe Links wird die vollständige URL (Referer) gesendet; Sitzungs-/Datenschutzinformationen können abfließen. Fehlt auf ALLEN 8 geprüften einzigartigen Seiten. |
| Sicherheits-Header fehlt: Permissions-Policy | Mittel | Sensible APIs wie Kamera/Mikrofon/Standort sind nicht eingeschränkt; Drittinhalte könnten sie missbrauchen. Fehlt auf ALLEN 8 geprüften einzigartigen Seiten. |

## POSITIVE ZUSICHERUNG — GEPRÜFTE BEREICHE

Einschließlich der Bereiche ohne Befund wurden die Prüfungen des Einfachen Scans auf **8 eindeutigen Seiten** einschließlich der Startseite tatsächlich ausgeführt. Die folgende Tabelle zeigt transparent auch die Ergebnisse „kein Problem gefunden":

| Prüfbereich | Ergebnis |
|---------------|-------|
| HTTP-Sicherheits-Header (auf 8 Seiten) | ⚠️ Befund vorhanden (6/6 empfohlene Header fehlen — oben ausführlich) |
| TLS / Zertifikat | ⚠️ Befund vorhanden (HTTPS antwortete nicht — unverschlüsselte Kommunikation) |
| Server-/Software-Versionssignatur (auf 8 Seiten) | ✅ Kein Problem gefunden (keine bekannte veraltete/EOL-Versionssignatur erkannt) |

> **Drei-Zustands-Unterscheidung (Ehrlichkeit):** ✅ *Kein Problem gefunden* = Prüfung lief, sauberes Ergebnis · ⚠️ *Befund vorhanden* = oben ausführlich · ⚠️ *Nicht überprüfbar* = keine Daten erhoben (bedeutet NICHT sicher).

### Was dieses Paket prüft und was NICHT

**PRÜFT (passiv — nur Seitenabruf per GET, es wird keine Sonde/kein Payload gesendet):** HTTP-Sicherheits-Header, TLS-/Zertifikatsstatus (Gültigkeit · Hostname · TLS-Version), Server-Software-Versionssignatur und Erkennung bekannter veralteter/EOL-Versionen — auf den 8 entdeckten Seiten.

**PRÜFT NICHT:** CORS-Richtlinie, Details der Cookie-Flags, Content-Security-Policy-Analyse, DNS-/E-Mail-Einträge (SPF/DKIM/DMARC) und Suche nach offen zugänglichen sensiblen Dateien sind im Paket **Externe Angriffsfläche**; die Zuordnung zu DSGVO/PCI/ISO-Rahmenwerken im Paket **Compliance**; Subdomain-/API-/CVE-Discovery im Paket **Reconnaissance**; die aktive Schwachstellenverifikation (SQLi/XSS/IDOR-Sonde) in den Paketen **Aktive Verifikation** und **Umfassender Pentest**. Dieser Bericht beruht auf passiver Beobachtung; „kein Befund" **BEWEIST NICHT**, dass es sicher ist, da kein aktiver Angriff versucht wurde.
