Dieser Abschnitt enthält Korrekturvorschläge für die in den ausgeführten aktiven Verifikationskontrollen festgestellten Befunde.

### Injektions-(SQLi/XSS)-Verifikation

### Injektion (SQLi/XSS) — Korrektur

- **SQLi:** Schreiben Sie alle Datenbankabfragen mit **parametrisierten Abfragen / Prepared Statements**; fügen Sie Benutzereingaben niemals als String in die Abfrage ein. Wenn Sie ein ORM verwenden, vermeiden Sie das Verketten von rohem SQL. Zeigen Sie dem Endbenutzer keine Datenbank-Fehlermeldungen an.
- **XSS:** Wenden Sie beim Ausgeben von Benutzereingaben in HTML eine **kontextgerechte Ausgabekodierung** (HTML-Entity-Encoding) an; verwenden Sie nach Möglichkeit eine Template-Engine mit automatischem Escaping. Beschränken Sie Inline-Skripte mit dem `Content-Security-Policy`-Header.
- Testen Sie nach der Behebung dieselben Einstiegspunkte erneut.

### Unbefugter-Zugriff-(IDOR)-Verifikation

### Unbefugter Zugriff (IDOR) — Korrektur

- **Objektebenen-Autorisierung:** Verifizieren Sie bei jedem Ressourcenzugriff serverseitig, ob der anfragende Benutzer ein Zugriffsrecht auf dieses Objekt hat (dass die ID gültig ist, reicht allein nicht aus).
- **Nicht erratbare Bezeichner:** Verwenden Sie statt sequenzieller numerischer IDs UUIDs/zufällige Bezeichner; erschweren Sie die Aufzählung.
- Stellen Sie Ressourcen, die nicht öffentlich zugänglich sein sollen, hinter eine Authentifizierung.

### SSRF-Verifikation

### SSRF — proaktive Härtung

- Wenden Sie in allen Feldern, die eine URL vom Benutzer entgegennehmen, eine serverseitige **Allowlist** + Sperrung des internen Netzwerks an (proaktiv).
- Setzen Sie bei erforderlichem externen Fetch Schema-/Host-Verifikation + Timeout + Größenlimit.

### Datei-Upload-Verifikation

### Datei-Upload — proaktive Härtung

- Wenden Sie an Upload-Endpunkten serverseitige Typ-/MIME-Verifikation + Allowlist + Speicherung außerhalb des Web-Roots an (proaktiv).

### Geschäftslogik-Verifikation

### Geschäftslogik — proaktive Härtung

- Verifizieren Sie kritische Werte (Preis/Menge) serverseitig; wenden Sie in mehrstufigen Abläufen eine Schrittreihenfolgeprüfung an (proaktiv).

### Race- / Mass-Assignment-Verifikation

### Race / Mass-Assignment — proaktive Härtung

- Wenden Sie beim Model-Binding eine Feld-Allowlist (Mass-Assignment-Schutz) an; verwenden Sie bei kritischen Operationen ein atomares/idempotentes Design (proaktiv).

### RCE- / Command-Injection-Verifikation

### RCE / Command-Injection — proaktive Härtung

- Überprüfen Sie Codepfade, die Systembefehle aufrufen; verifizieren Sie Eingaben mit einer Allowlist, vermeiden Sie Shell-String-Verkettung (proaktiv).
- Wenden Sie geringste Rechte + Einschränkung des ausgehenden Netzwerkverkehrs an.

### Login-Bypass (SQLi-Indikator)

### Login-Bypass / SQL-Injektion — Korrektur

- Verwenden Sie in Authentifizierungsabfragen **parametrisierte Abfragen / Prepared Statements**; setzen Sie Benutzereingaben niemals direkt in SQL ein.
- Eingabevalidierung + sichere ORM-APIs; geben Sie bei fehlerhafter Eingabe eine einheitliche Fehlermeldung zurück.
