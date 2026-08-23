#!/usr/bin/env python3
"""
(OTONOM AI RED TEAM — 3b-ii) GENEL KANIT-BAĞLAYICI.
Disiplin: bir bulgu YALNIZ ham artefakta (konteyner terminal stdout'u / gerçek komut çıktısı)
bağlıysa kanıtlıdır — ajanın SÖZÜNE (subtask/agentlog anlatısı) ASLA güvenilmez.

3 katman:
  KANITLI  — ham artefaktta kategoriye özgü DETERMİNİSTİK imza var (ya da davranışsal SQLi anomalisi).
  BELİRSİZ — iddiaya bağlı artefakt VAR ama kesin imza YOK -> silinmez, insan-inceleme.
  HAYALET  — iddiayı destekleyen ham artefakt YOK (sıfır iz) -> elenir (rapora girmez).

Girdi:
  --flow <id>       PentAGI Postgres'ten oku (canlı droplet; docker exec pgvector psql).
  --input <a.json>  Mock/dışa-aktarılmış {claims:[...], artifacts:[...]} oku (DB'siz smoke-test).
Çıktı:
  --json            Yapısal JSON (rapor motoru bunu tüketir). Yoksa insan-okur özet.
"""
import sys, re, json, argparse, subprocess

# ————————————————————— DETERMİNİSTİK İMZA AİLELERİ (yalnız HAM artefakt metninde) —————————————————————
SIG = {
    'sqli':            r'SQLITE_ERROR|SQL syntax|unrecognized token|near "[^"]*": syntax error|ORA-\d{5}|mysql_fetch|PostgreSQL query failed|SQLSTATE\[',
    'lfi':             r'root:x:0:0:|\[boot loader\]|for 16-bit app support',
    'path_traversal':  r'root:x:0:0:|\[boot loader\]|\[extensions\]',
    'info_disclosure': r'stack trace|Traceback \(most recent call last\)|\n\s+at [\w.$<>]+ \([^)]*:\d+:\d+\)|ENOENT|EACCES|SequelizeDatabaseError|/juice-shop/',
    'rce':             r'uid=\d+\([^)]*\) gid=\d+\([^)]*\)|Microsoft Windows \[Version|root@[\w.-]+:',
    'ssrf':            r'\bInstanceId\b|ami-[0-9a-f]{8,}|metadata\.google|169\.254\.169\.254',
    'xxe':             r'root:x:0:0:|<!DOCTYPE[^>]*SYSTEM',
}
# İddia metninden kategori tahmini (Türkçe + İngilizce anahtar kelimeler).
CAT_KEYWORDS = {
    'sqli': ['sql injection', 'sqli', 'sql enjeksi', 'union-based', 'union based', 'sqlite', 'boolean-based', 'error-based'],
    'lfi': ['lfi', 'local file inclusion', 'yerel dosya'],
    'path_traversal': ['path traversal', 'directory traversal', 'dizin geçiş', '/etc/passwd', 'dosya geçiş'],
    'info_disclosure': ['information disclosure', 'info disclosure', 'bilgi ifş', 'verbose error', 'stack trace', 'hata ifş'],
    'rce': ['remote code execution', 'rce', 'command injection', 'komut enjeksi', 'kod çalıştır'],
    'ssrf': ['ssrf', 'server-side request forgery', 'sunucu taraflı istek'],
    'xxe': ['xxe', 'xml external entity'],
    'xss': ['xss', 'cross-site scripting', 'çapraz site'],
    'open_redirect': ['open redirect', 'açık yönlendirme'],
}
# Kabaca şiddet (yalnız KANITLI bulgularda genel-risk için; asla şişirilmez).
SEVERITY = {'rce': 'kritik', 'sqli': 'yüksek', 'lfi': 'yüksek', 'path_traversal': 'yüksek', 'xxe': 'yüksek',
            'ssrf': 'orta', 'info_disclosure': 'orta', 'xss': 'orta', 'open_redirect': 'düşük', 'bilinmeyen': 'düşük',
            'security_header': 'düşük', 'cookie_config': 'düşük'}
SEV_ORDER = {'kritik': 4, 'yüksek': 3, 'orta': 2, 'düşük': 1, 'temiz': 0}
CAT_LABEL = {'xss': 'Reflected XSS', 'sqli': 'SQL Enjeksiyonu', 'lfi': 'Yerel Dosya Dahil Etme',
             'path_traversal': 'Dizin Geçişi', 'rce': 'Uzaktan Kod Çalıştırma', 'ssrf': 'SSRF',
             'xxe': 'XML Dış Varlık', 'info_disclosure': 'Bilgi İfşası', 'open_redirect': 'Açık Yönlendirme',
             'security_header': 'Eksik Güvenlik Başlığı', 'cookie_config': 'Çerez Güvenlik Bayrağı',
             'bilinmeyen': 'Genel Bulgu'}

# ————————————————————— "BULGU MU?" FİLTRESİ (P0-1) — ajan plan/araştırma/meta'sı KANIT/BULGU DEĞİL —————
# KANIT yalnız GERÇEK istek/yanıt taşıyan 'terminal' artefaktıdır (curl + HTTP). Plan/arama/hafıza/tamamlama
# mesajları (memorist/search/subtask_list/hack_result/done...) rapora GİRMEZ — ne kanıtlı, ne belirsiz, ne
# hayalet; filtrelenir. Bu, "her ajan cümlesini bulgu sanma" + "plan metnini kanıt bağlama" deliğini kapatır.
EVIDENCE_KINDS = {'terminal'}
META_CLAIM_RE = re.compile(
    r'(ortam hazırlığı|pasif keşif|uygulama haritalama|endpoint keşf|nihai rapor|vector database|'
    r'known endpoints|no historical|subtask\s*\d*\s*(complete|tamamlan|başar)|connection discipline|'
    r'evidence log|keşif|haritalama|araştırma|hazırlık|test edilmesi|göstergeler|analizi|eşleştir|'
    r'doğrulanması|research|reconnaissance|preparation|plan\b|planla)', re.I)
# İstek (curl) o kategoriye ait bir payload GÖNDERDİ mi — imza yalnız gerçekten prob atılmış istekte sayılır.
PROBE_RE = {
    # sqli: bare `'`/`--` KALDIRILDI — shell tırnaklarını (echo '...') ve curl bayraklarını (--resolve)
    # yanlış eşleştiriyordu → XSS probu "SQLi probladı" sanılıyordu. Yalnız gerçek SQLi jetonları.
    'sqli': r"%27|\bunion\b\s+\bselect\b|\bor\b\s+1\s*=\s*1|\band\b\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|waitfor\s+delay|'\s*or\s*'|'\s*--|'\s*#",
    'lfi': r"\.\./|/etc/passwd|boot\.ini|%2e%2e",
    'path_traversal': r"\.\./|%2e%2e",
    'rce': r";\s*id\b|\|\s*id\b|`id`|\bwhoami\b|\bcat\b\s+/etc|%3bid",
    'xxe': r"<!DOCTYPE|SYSTEM\s",
    'ssrf': r"169\.254\.169\.254|metadata|localhost|127\.0\.0\.1|file://",
}

# (D2) ALTYAPI/ARAÇ HATASI — bir güvenlik bulgusu DEĞİL; kategoriye (SQLi/XSS) ZORLA eşlenmesin, ELENSİN.
# Kanıt: rapor konteyner-çalıştırma hatasını ("OCI runtime exec failed ... chdir to cwd") "SQL Enjeksiyonu"
# diye etiketlemişti. İÇERİK-tabanlı filtre (tür değil): çıktı bir araç/altyapı hata imzasıysa aday olmaz.
_TOOL_ERROR_RE = re.compile(
    r'OCI runtime exec failed|unable to start container process|chdir to cwd|set in config\.json|'
    r'docker:\s*Error response from daemon|exec failed:|cannot exec|containerd|runc:', re.I)

def is_tool_error(a):
    """rawText bir konteyner/araç çalıştırma hatası mı (gerçek HTTP yanıtı DEĞİL)? Öyleyse kanıt sayılmaz."""
    raw = a.get('rawText', '') or ''
    return bool(_TOOL_ERROR_RE.search(raw)) and 'HTTP/' not in raw

# (D1) HTTP yanıt ayrıştırma: terminal blob'unda İSTEK-YANKISI (echo'lanan curl komutu) HTTP satırından
# ÖNCEdir; GERÇEK yanıt = "HTTP/1.x <status>" satırından sonra, başlıkların ARDINDAKİ boş satırdan sonraki
# GÖVDE. reflected-XSS "kanıtlı" için: (a) durum kodu 2xx olmalı (4xx/5xx = istek reddedildi → kanıt değil),
# (b) marker YALNIZ gövdede aranmalı (echo'lanan istek satırındaki marker "ne göndereceğiz"tir, kanıt değil).
_HTTP_STATUS_RE = re.compile(r'HTTP/\d(?:\.\d)?\s+(\d{3})')

def parse_http(raw):
    """Terminal blob'undan SON HTTP yanıtını ayrıştır → (status:int|None, body:str)."""
    if not raw:
        return None, ''
    matches = list(_HTTP_STATUS_RE.finditer(raw))
    if not matches:
        return None, ''
    m = matches[-1]                      # yönlendirme zinciri olursa SON yanıt
    status = int(m.group(1))
    after = raw[m.end():]
    sep = re.search(r'\r?\n\r?\n', after)  # başlık bloğu ↔ gövde ayıracı (ilk boş satır)
    body = after[sep.end():] if sep else ''
    return status, body

def http_header_block(raw):
    """HTTP durum satırından sonraki başlık bloğunu {küçük-harf: değer} olarak döndür (ilk boş satıra kadar)."""
    if not raw:
        return {}
    m = _HTTP_STATUS_RE.search(raw)
    if not m:
        return {}
    after = raw[m.end():]
    sep = re.search(r'\r?\n\r?\n', after)
    block = after[:sep.start()] if sep else after
    hdrs = {}
    for line in block.split('\n'):
        if ':' in line:
            k, v = line.split(':', 1)
            key = k.strip().lower()
            hdrs[key] = (hdrs[key] + ' ' + v.strip()) if key in hdrs else v.strip()
    return hdrs

# (P0-1 madde 4-5) Deterministik pasif config gözlemleri — GERÇEK response başlıklarından, LLM YOK.
_SECURITY_HEADERS = {
    'x-frame-options': 'Clickjacking koruması yok (X-Frame-Options)',
    'content-security-policy': 'İçerik Güvenlik Politikası yok (Content-Security-Policy)',
    'x-content-type-options': 'MIME-sniffing koruması yok (X-Content-Type-Options: nosniff)',
    'strict-transport-security': 'HSTS yok (Strict-Transport-Security)',
}

def passive_config_findings(artifacts, target_host, target_ip):
    """GERÇEK yanıt başlıklarından deterministik KANITLI config bulguları (düşük şiddet): Server sürüm
    ifşası, cookie güvenlik bayrağı eksiği, güvenlik-başlığı eksiği. Yalnız hedefe atılmış 2xx/3xx yanıtlar."""
    out = []
    def emit(cat, endp, detail, a, sev, marker='', title=None, missing=None):
        # (P0-2b) Başlık HAM KANIT'te GÖRÜLEN veriyle birebir: jenerik "biri/birkaçı eksik" YERİNE gerçekten
        # eksik olan bayrak/başlık isimle yazılır. title verilmezse CAT_LABEL+endpoint'e düşer.
        ev = {'artifactRef': a.get('id', '?'), 'signature': 'response-header', 'detail': detail, **_mk_evidence(a)}
        if marker:
            ev['marker'] = marker                              # P0-3: raporun vurgulayacağı ham satır anahtarı
        if missing:
            ev['missing'] = missing                            # (P0-9) yalnız GERÇEKTEN eksik olan(lar) → flag-spesifik İŞ ETKİSİ
        ttl = title or f"{CAT_LABEL.get(cat, cat)}{(' — ' + endp) if endp else ''}"
        out.append({'title': ttl, 'category': cat,
                    'endpoint': endp, 'severity': sev, 'tier': 'KANITLI', 'evidence': ev,
                    'reason': detail})   # (P0-2b) reason = spesifik gözlem (jenerik değil)
    # Her config türü SUNUCU-GENELİ olduğundan bir KEZ raporlanır (uç başına tekrar = gürültü).
    srv_done = cookie_done = hdr_done = False
    for a in artifacts:
        if not (artifact_is_evidence(a) and is_http_artifact(a)):
            continue
        cmd = a.get('command', '') or ''; raw = a.get('rawText', '') or ''
        if off_target_request(a, {'text': cmd}, target_host, target_ip):
            continue
        st, _ = parse_http(raw)
        # Yalnız BAŞARILI/YÖNLENDİRME (2xx/3xx) yanıtları — uygulamaya GERÇEKTEN ulaşıldığında. 4xx/5xx
        # reddedilen prob yanıtıdır; onun başlıklarından config bulgusu çıkarmak gürültü olur.
        if st is None or not (200 <= st < 400):
            continue
        hdrs = http_header_block(raw)
        endp = (request_endpoint(cmd) or '/').split('?')[0]         # temiz PATH (payload'suz)
        if not srv_done:
            srv = hdrs.get('server', '')
            if re.search(r'\d', srv):
                srv_done = True
                emit('info_disclosure', '', f"Server başlığı sürüm/teknoloji ifşa ediyor: {srv[:70]!r} (sunucu geneli)", a, 'düşük',
                     marker='Server:', title=f"Bilgi İfşası — Server başlığı sürüm/teknoloji açığa çıkarıyor ({srv[:40]})")
        if not cookie_done:
            sc = hdrs.get('set-cookie', '')
            if sc:
                _CANON = {'httponly': 'HttpOnly', 'secure': 'Secure', 'samesite': 'SameSite'}
                present = [_CANON[f] for f in ('httponly', 'secure', 'samesite') if f in sc.lower()]
                miss = [_CANON[f] for f in ('httponly', 'secure', 'samesite') if f not in sc.lower()]
                if miss:
                    cookie_done = True
                    # (P0-2b) Yalnız GERÇEKTEN eksik bayrağı isimle yaz + mevcut olanları da belirt (kanıtla birebir).
                    det = f"Set-Cookie eksik güvenlik bayrağı: {', '.join(miss)}" + (f" — {', '.join(present)} zaten mevcut" if present else "") + " (oturum çerezi)"
                    emit('cookie_config', endp, det, a, 'düşük', marker='Set-Cookie',
                         title=f"Çerez Güvenlik Bayrağı Eksik: {', '.join(miss)}", missing=miss)
        if not hdr_done and 200 <= st < 300:
            hdr_done = True
            miss = [d for h, d in _SECURITY_HEADERS.items()
                    if h not in hdrs and (h != 'strict-transport-security' or 'https' in cmd.lower())]
            if miss:
                # (P0-2b) Yalnız gerçekten eksik başlık(lar) isimlendirilir (miss zaten sadece eksikleri içerir).
                _hnames = [h.split('(')[-1].rstrip(')') if '(' in h else h for h in miss]
                emit('security_header', endp, 'Eksik güvenlik başlıkları — ' + '; '.join(miss), a, 'düşük', marker='HTTP/',
                     title='Eksik Güvenlik Başlığı: ' + ', '.join(_hnames))
    return out

def tried_summary(artifacts):
    """P0-2 'Pozitif güvence' + P1 exec: gerçek artefakt sayaçlarından denenen kapsam (LLM YOK)."""
    ev = [a for a in artifacts if artifact_is_evidence(a)]
    http = [a for a in ev if is_http_artifact(a)]
    endpoints = set()
    for a in http:
        e = request_endpoint(a.get('command', '')).split('?')[0]
        # HTML-etiket parçalarını (</script> → /script gibi) ele — bunlar endpoint değil.
        if e and e != '/' and not re.fullmatch(r'/(script|style|body|html|div|span|br|img|a|p|head)', e):
            endpoints.add(e)
    fams = set()
    for a in http:
        cmd = (a.get('command', '') or '').lower()
        if 'zqxmarker' in cmd or '<script' in cmd or '%3cscript' in cmd:
            fams.add('XSS')
        for cat in ('sqli', 'lfi', 'rce', 'path_traversal', 'ssrf'):
            if request_probes(cat, cmd):
                fams.add(CAT_LABEL.get(cat, cat))
    return {'httpRequests': len(http), 'terminalArtifacts': len(ev), 'endpointCount': len(endpoints),
            'endpoints': sorted(endpoints)[:25], 'families': sorted(fams)}

def is_http_artifact(a):
    """Artefakt GERÇEK bir HTTP istek/yanıtı mı içeriyor? (recon shell çıktısı — ls/mkdir/dizin listesi —
    bir zafiyet kanıtı olamaz). HTTP durum satırı VEYA curl komutu VEYA HTML gövdesi varsa evet."""
    raw = a.get('rawText', '') or ''
    cmd = a.get('command', '') or ''
    return bool(_HTTP_STATUS_RE.search(raw)) or 'curl' in cmd.lower() or bool(re.search(r'<html|<!doctype|<body', raw, re.I))

def artifact_is_evidence(a):
    """KANIT = gerçek istek/yanıt taşıyan terminal artefaktı (kind='terminal'). Plan/arama/meta DEĞİL."""
    return (a.get('kind') or '') in EVIDENCE_KINDS

def request_endpoint(cmd):
    """curl/komuttan İSTENEN path?query (host'tan sonra). Uydurma değil; gerçek istek satırından."""
    m = re.search(r'https?://[a-z0-9.\-]+(/[^\s"\'\\]*)', cmd or '', re.I)
    if m:
        return m.group(1)[:120]
    # URL yoksa: dosya-sistemi yollarını (cwd/mkdir: /root /work /tmp ...) ATLA — bunlar endpoint değil.
    for mm in re.finditer(r'(/[\w./?=%&\-]{2,120})', cmd or ''):
        p = mm.group(1)
        if re.match(r'/(root|work|tmp|opt|var|home|etc|usr|bin|dev|proc|sys|mnt|run)\b', p):
            continue
        return p
    return ''

def is_finding_claim(c):
    """P0-1: iddia bir GÜVENLİK BULGUSU adayı mı? subtask/agentlog plan/narrative → HAYIR. Yalnız net
    zafiyet iddiası (kategori tespit edildi) + GERÇEK path/param + plan-başlığı DEĞİL ise aday olur."""
    title = c.get('title') or ''; text = c.get('text') or ''
    if META_CLAIM_RE.search(title) or META_CLAIM_RE.search(text[:120]):
        return False
    if detect_category(f"{title} {text}") == 'bilinmeyen':
        return False
    ep = extract_endpoint(text)
    if not ep or ep.startswith('/root') or ep.split('?')[0] in ('/yanıt', '/hata', '/cookie', '/san', '/hcl', '/'):
        return False
    return True

def request_probes(cat, cmd):
    """İstek o kategoriye ait bir payload taşıyor mu (info_disclosure isteğe özel payload gerektirmez)."""
    if cat == 'info_disclosure':
        return True
    p = PROBE_RE.get(cat)
    return bool(p and re.search(p, cmd or '', re.I))


def detect_category(text):
    t = (text or '').lower()
    for cat, kws in CAT_KEYWORDS.items():
        if any(k in t for k in kws):
            return cat
    return 'bilinmeyen'


def extract_endpoint(text):
    m = re.search(r'(/[\w./?=%&-]{1,120})', text or '')
    return (m.group(1).split()[0] if m else '')


def relates(artifact, claim, cat):
    """İddia ile artefakt ilişkili mi: endpoint yolu ya da payload örtüşmesi (kaba, muhafazakâr)."""
    art = (artifact.get('rawText', '') + ' ' + artifact.get('command', '')).lower()
    ep = extract_endpoint(claim.get('text', '')).lower()
    if ep and len(ep) > 3 and ep.split('?')[0] in art:
        return True
    # payload/örnek token örtüşmesi (güvenli literaller)
    for tok in re.findall(r"%27|\.\./|<script|--|\bunion\b", claim.get('text', '').lower()):
        if tok in art:
            return True
    return False


def behavioral_sqli(cat, related, all_artifacts):
    """Davranışsal SQLi: bozuk payload'lı yanıt, baseline'dan ÇOK daha fazla satır/boyut döndürüyor."""
    if cat != 'sqli':
        return None
    # baseline = zararsız istek (en küçük item), inject = ' ya da -- içeren, çok item dönen
    injects = [a for a in related if re.search(r"%27|'|--|union", (a.get('command', '') + a.get('rawText', '')), re.I)]
    baselines = [a for a in all_artifacts if a.get('items') is not None and not re.search(r"%27|'|--|union", a.get('command', ''), re.I)]
    if not injects or not baselines:
        return None
    base_items = min((a.get('items', 0) for a in baselines), default=0)
    for a in injects:
        it = a.get('items', 0)
        if it and it >= max(2 * base_items, base_items + 5):
            return {'artifactRef': a.get('id', '?'), 'signature': 'davranışsal (satır şişmesi)',
                    'detail': f"bozuk payload => {it} kayıt (baseline {base_items}); deterministik & tekrarlanabilir"}
    return None


def reflected_xss(cat, related):
    """Reflected XSS: request'te gönderilen payload/marker, RESPONSE gövdesinde ENCODE EDİLMEDEN yansıyor.
    Deterministik: aynı dize yanıtta birebir (&lt; değil <) → KANITLI. demo.testfire /search.jsp?query= vakası."""
    if cat != 'xss':
        return None
    for a in related:
        # NEEDLE YALNIZ İSTEKTEN (command): reflected XSS payload'ı ajanın GÖNDERDİĞİ şeydir.
        cmd = a.get('command', '')
        raw = a.get('rawText', '')
        # (D1) GERÇEK HTTP yanıtı ayrıştır: durum kodu 2xx OLMALI (4xx/5xx = istek reddedildi → kanıt DEĞİL);
        # marker YALNIZ GÖVDEde aranır — echo'lanan istek satırındaki (HTTP satırından ÖNCE) marker SAYILMAZ.
        status, body = parse_http(raw)
        if status is None or not (200 <= status < 300):
            continue
        for m in re.finditer(r'(zqx[a-z0-9]*marker[a-z0-9]*|<script\b[^>]*>|<img\b[^>]*>|["\'>]<[a-z]{1,10}[ >/])', cmd, re.I):
            marker = m.group(0)
            if marker in body:
                idx = body.find(marker)
                around = body[max(0, idx - 4):idx + len(marker) + 4]
                if '&lt;' not in around and '&gt;' not in around and '%3c' not in around.lower():
                    # (P0-3) Kanıt kutusu için REFLECTION noktasına ODAKLI ham kesit — gövdenin başı 1000-char
                    # cap'ine takılıp reflection'ı kaçırmasın diye burada üretilir (dump değil, satır penceresi).
                    fs = max(0, idx - 180); fe = min(len(body), idx + len(marker) + 180)
                    focus = redact(body[fs:fe])
                    excerpt = f"HTTP/1.1 {status} (gerçek yanıt · gövde kısaltıldı, reflection çevresi)\n…\n{focus}"
                    return {'artifactRef': a.get('id', '?'), 'signature': 'reflected-unencoded', 'marker': marker,
                            'rawExcerpt': excerpt[:1200],
                            'detail': f"payload {marker[:34]!r} HTTP {status} yanıt GÖVDESİNDE ENCODE EDİLMEDEN yansıdı → reflected XSS"}
    return None


# ————————————————————— REDAKSİYON (ham kanıtta secret/PII gösterme) —————————————————————
def redact(text):
    t = str(text or '')
    t = re.sub(r'sk-ant-[A-Za-z0-9_\-]{8,}', 'sk-ant-***', t)
    t = re.sub(r'dop_v1_[A-Za-z0-9]{16,}', 'dop_v1_***', t)
    t = re.sub(r'eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{4,}', 'JWT.***', t)
    t = re.sub(r'(?i)\b(authorization|bearer|api[_-]?key|password|passwd|secret|token|set-cookie|cookie)\b\s*[:=]\s*\S+', r'\1: ***', t)
    t = re.sub(r'\b[A-Fa-f0-9]{32,}\b', '***hex***', t)                       # uzun hex (anahtar/hash)
    t = re.sub(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', '***@***', t)  # e-posta (PII)
    return t

# ————————————————————— PROVENANCE (İSTEĞİN ATILDIĞI host'a göre; yanıt gövdesine DEĞİL) —————————————
# KRİTİK: provenance yalnız isteğin GERÇEKTEN gönderildiği host'a bakar (curl URL host / Host header /
# --resolve host). Yanıt GÖVDESİNDE geçen başka domain linkleri (ör. altoromutual.com) ya da --resolve'un
# IP kısmı (65.61.137.117 = hedefin PINLENEN IP'si) provenance'ı ETKİLEMEZ — onlar hedefin kendi içeriği.
def request_hosts(command):
    c = command or ''
    hs = set()
    for m in re.finditer(r'https?://([a-z0-9.\-]+)', c, re.I): hs.add(m.group(1).lower())          # URL host
    for m in re.finditer(r'-H\s*["\']?\s*host:\s*([a-z0-9.\-]+)', c, re.I): hs.add(m.group(1).lower())  # Host header
    for m in re.finditer(r'--resolve\s+([a-z0-9.\-]+):', c, re.I): hs.add(m.group(1).lower())      # --resolve HOST (ip değil)
    return hs

def is_target_host(h, target_host, target_ip):
    th = (target_host or '').lower(); base = '.'.join(th.split('.')[-2:]) if th.count('.') >= 1 else th
    return bool(h) and (h == th or h == 'www.' + th or h == (target_ip or '') or (base and (h == base or h.endswith('.' + base))))

def off_target_request(bound, claim, target_host, target_ip):
    """İstek hedef/IP/www DIŞI bir domain'e mi atıldı? Öyleyse o host'u döndür (off-target), değilse None."""
    cmd = (bound or {}).get('command', '') or ''
    hs = request_hosts(cmd) or request_hosts(claim.get('text', ''))
    if not hs:
        return None                                              # host belirlenemedi (saf IP isteği zaten hedef) → tut
    if any(is_target_host(h, target_host, target_ip) for h in hs):
        return None                                              # istek host'larından biri hedef → hedefe ait, tut
    foreign = [h for h in hs if not is_target_host(h, target_host, target_ip)]
    return foreign[0] if foreign else None                       # hepsi yabancı → off-target (ör. juiceshop)


def _mk_evidence(a):
    return {'rawExcerpt': redact(a.get('rawText', ''))[:1000], 'command': redact(a.get('command', ''))[:200]}

def classify(claims, artifacts, target_host='', target_ip=''):
    """KANIT-TEMELLİ üç-katman. KANIT yalnız gerçek istek/yanıt (terminal) artefaktından gelir; plan/meta
    iddialar FİLTRELENİR (rapora girmez). Dönüş: (findings, filtered_meta_count)."""
    findings = []
    seen = set()      # dedup (kategori, endpoint-yolu)
    filtered = 0      # bulgu-DEĞİL (plan/meta) sayısı
    # (D2) Kanıt havuzu: terminal artefaktları AMA altyapı/araç hatası olanlar (OCI/konteyner) HARİÇ —
    # bunlar bir güvenlik bulgusuna kategorize edilemez, elenmeli (SQLi/XSS diye etiketlenmesin).
    ev_arts = [a for a in artifacts if artifact_is_evidence(a) and not is_tool_error(a)]

    def add(cat, endpoint, tier, ev, reason, sev=None):
        key = (cat, (endpoint or '').split('?')[0])
        if key in seen:          # aynı zafiyet (kategori+endpoint) tek kayda indir (dedup)
            return
        seen.add(key)
        findings.append({'title': f"{CAT_LABEL.get(cat, cat)}{(' — ' + endpoint) if endpoint else ''}",
                         'category': cat, 'endpoint': endpoint, 'severity': sev or SEVERITY.get(cat, 'düşük'),
                         'tier': tier, 'evidence': ev, 'reason': reason})

    # ——— (1) KANIT-TEMELLİ: yalnız gerçek istek/yanıt (terminal) artefaktlarında deterministik imza ———
    for a in ev_arts:
        cmd = a.get('command', '') or ''
        if off_target_request(a, {'text': cmd}, target_host, target_ip):
            continue
        endp = request_endpoint(cmd)
        rx = reflected_xss('xss', [a])                     # marker istek + yanıtta ENCODE-EDİLMEDEN (gerçek HTTP)
        if rx:
            ev = _mk_evidence(a); ev.update(rx)            # rx ODAKLI rawExcerpt'i (P0-3) generic 1000-char'ı EZER
            add('xss', endp, 'KANITLI', ev, 'reflected XSS — payload GERÇEK yanıt gövdesinde ENCODE EDİLMEDEN yansıdı')
            continue
        raw = a.get('rawText', '') or ''
        for cat, sig_re in SIG.items():                    # yanıt gövdesinde imza — İSTEK o kategoriyi PROBLADIYSA
            if not request_probes(cat, cmd):
                continue
            m = re.search(sig_re, raw, re.I)
            if m:
                ev = {'artifactRef': a.get('id', '?'), 'signature': m.group(0)[:60],
                      'detail': f"gerçek YANITTA deterministik imza: {m.group(0)[:60]!r}", **_mk_evidence(a)}
                add(cat, endp, 'KANITLI', ev, 'gerçek istek/yanıtta deterministik imza (istek o kategoriyi probladı)')
                break
    beh = behavioral_sqli('sqli', ev_arts, ev_arts)        # davranışsal SQLi (satır şişmesi) — yalnız kanıt artefaktları
    if beh:
        ba = next((a for a in ev_arts if a.get('id') == beh.get('artifactRef')), None)
        if ba and not off_target_request(ba, {'text': ba.get('command', '')}, target_host, target_ip):
            beh.update(_mk_evidence(ba))
            add('sqli', request_endpoint(ba.get('command', '')), 'KANITLI', beh, 'davranışsal SQLi (baseline üstü satır şişmesi)')

    # ——— (2) İDDİA-TEMELLİ: yalnız GERÇEK güvenlik iddiası (plan/meta filtrelenir) + KANIT artefaktı ———
    for c in claims:
        if not is_finding_claim(c):
            filtered += 1                                  # plan/meta/araştırma/tamamlama → rapora GİRMEZ
            continue
        cat = detect_category(f"{c.get('title', '')} {c.get('text', '')}")
        # yalnız GERÇEK HTTP istek/yanıtı taşıyan artefaktlar bir bulguyu destekleyebilir — shell keşif
        # çıktısı (ls/mkdir/"total 8 drwxr-xr-x", cwd=/work) bir zafiyet kanıtı DEĞİLdir (P0-2). Aksi halde
        # "Light SQLi probing" gibi bir PLAN maddesi bir dizin-listelemesine bağlanıp sahte BELİRSİZ üretiyordu.
        related = [a for a in ev_arts if relates(a, c, cat) and is_http_artifact(a)]
        if not related:
            add(cat, extract_endpoint(c.get('text', '')), 'HAYALET', None,
                'iddiayı destekleyen gerçek istek/yanıt kanıtı yok (sıfır iz) -> elenir')
            continue
        bound = related[0]
        if off_target_request(bound, c, target_host, target_ip):
            continue
        sig_re = SIG.get(cat)
        m = re.search(sig_re, bound.get('rawText', ''), re.I) if sig_re else None
        hit = m if (m and request_probes(cat, bound.get('command', ''))) else None  # imza + istek o kategoriyi probladı
        endp = request_endpoint(bound.get('command', '')) or extract_endpoint(c.get('text', ''))
        if hit:
            ev = {'artifactRef': bound['id'], 'signature': hit.group(0)[:60],
                  'detail': f"gerçek YANITTA deterministik imza: {hit.group(0)[:60]!r}", **_mk_evidence(bound)}
            add(cat, endp, 'KANITLI', ev, 'gerçek istek/yanıtta deterministik imza')
        elif request_probes(cat, bound.get('command', '')):
            # İstek GERÇEKTEN bu kategoriyi probladı (ör. SQLi payload'ı gönderildi) ama kesin imza yok → insan-inceleme.
            ev = {'artifactRef': bound['id'], 'signature': '', 'detail': 'istek bu kategoriyi probladı, kesin imza yok', **_mk_evidence(bound)}
            add(cat, endp, 'BELIRSIZ', ev, 'istek bu kategoriyi probladı, kanıt var ama deterministik imza yok -> insan-inceleme')
        else:
            # HTTP artefaktı var AMA istek bu kategoriye ait bir payload GÖNDERMEMİŞ (yalnız plan/alakasız istek)
            # → gerçek kanıt yok, elenir. "Light SQLi probing" planının XSS-probuna bağlanıp BELİRSİZ üretmesini keser.
            add(cat, endp, 'HAYALET', None, 'iddia edilen kategoriye ait gerçek prob/istek yok (yalnız plan) -> elenir')

    # ——— (3) DETERMİNİSTİK PASİF CONFIG (P0-1 madde 4-5): gerçek yanıt başlıklarından, LLM YOK ———
    for pf in passive_config_findings(artifacts, target_host, target_ip):
        if (pf['category'], (pf['endpoint'] or '').split('?')[0]) not in seen:
            seen.add((pf['category'], (pf['endpoint'] or '').split('?')[0]))
            findings.append(pf)

    return findings, filtered


# ————————————————————— GİRDİ KAYNAKLARI —————————————————————
def load_from_json(path):
    d = json.load(open(path, encoding='utf-8'))
    return d.get('claims', []), d.get('artifacts', []), d.get('meta', {})


def _psql(sql):
    return subprocess.run(["docker", "exec", "pgvector", "psql", "-U", "postgres", "-d", "pentagidb", "-tAqc", sql],
                          capture_output=True, text=True).stdout


def load_from_pg(flow_id):
    NL = "\x01"
    # CLAIMS = subtasks.result + agentlogs.result (ajanın ne bulduğunu SÖYLEDİĞİ) — kanıt DEĞİL
    claims = []
    raw = _psql(f"SELECT id||'\t'||coalesce(title,'')||'\t'||replace(replace(coalesce(result,''),E'\\r',''),E'\\n','{NL}') "
                f"FROM subtasks WHERE task_id IN (SELECT id FROM tasks WHERE flow_id={flow_id}) ORDER BY id;")
    for line in raw.strip("\n").split("\n"):
        if not line.strip():
            continue
        sid, title, result = (line.split("\t", 2) + ['', ''])[:3]
        claims.append({'id': f"subtask#{sid}", 'title': title, 'text': (title + ' ' + result.replace(NL, ' '))})
    # ARTIFACTS = termlogs(type=stdout) — gerçek konteyner çıktısı (HAM KANIT)
    artifacts = []
    cmd_by = {}
    raw = _psql(f"SELECT id||'\t'||type||'\t'||replace(replace(coalesce(text,''),E'\\r',''),E'\\n','{NL}') "
                f"FROM termlogs WHERE flow_id={flow_id} ORDER BY id;")
    last_cmd = ''
    for line in raw.strip("\n").split("\n"):
        if not line.strip():
            continue
        tid, typ, text = (line.split("\t", 2) + ['', ''])[:3]
        text = re.sub(r"\x1b\[[0-9;]*m", "", text.replace(NL, "\n"))
        if typ == 'stdin':
            last_cmd = text.strip()
        elif typ == 'stdout':
            items = len(re.findall(r'"id":\d+', text))
            artifacts.append({'id': f"termlog#{tid}", 'kind': 'terminal', 'command': last_cmd, 'rawText': text, 'items': items})
            last_cmd = ''
    # TOOLCALLS = pentester/HTTP/terminal ARAÇ sonuçları — request/response BURADA olabilir (termlog DEĞİL).
    # 18→0 kök-nedeninin bir parçası: binder yalnız termlogs okuyordu; ajan HTTP'yi araç-çağrısıyla yaptıysa
    # kanıt toolcalls.result'ta kalıyordu → binder kör → her iddia HAYALET.
    raw = _psql(f"SELECT id||'\t'||coalesce(name,'')||'\t'||replace(replace(coalesce(args::text,''),E'\\r',''),E'\\n','{NL}')||'\t'||replace(replace(coalesce(result,''),E'\\r',''),E'\\n','{NL}') "
                f"FROM toolcalls WHERE flow_id={flow_id} ORDER BY id;")
    for line in raw.strip("\n").split("\n"):
        if not line.strip():
            continue
        tid, name, args, result = (line.split("\t", 3) + ['', '', ''])[:4]
        args = args.replace(NL, "\n"); result = result.replace(NL, "\n")
        blob = (args + "\n" + result).strip()
        if not blob:
            continue
        artifacts.append({'id': f"toolcall#{tid}", 'kind': (name or 'toolcall'), 'command': args[:300],
                          'rawText': blob, 'items': len(re.findall(r'"id":\d+', blob))})
    # AGENTLOGS = ajanın bulgu anlatısı (ek CLAIM kaynağı — subtask'ta olmayan bulgular burada olabilir).
    raw = _psql(f"SELECT id||'\t'||replace(replace(coalesce(result,''),E'\\r',''),E'\\n','{NL}') "
                f"FROM agentlogs WHERE flow_id={flow_id} ORDER BY id;")
    for line in raw.strip("\n").split("\n"):
        if not line.strip():
            continue
        aid, res = (line.split("\t", 1) + [''])[:2]
        res = res.replace(NL, ' ').strip()
        if res:
            claims.append({'id': f"agentlog#{aid}", 'title': res[:60], 'text': res})
    return claims, artifacts, {'flowId': flow_id}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--flow')
    ap.add_argument('--input')
    ap.add_argument('--target', default='')       # PINNED hedef host (provenance kuralı)
    ap.add_argument('--target-ip', dest='target_ip', default='')
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--trace', action='store_true')   # her artefaktın/iddianın kararını satır satır dök (teşhis)
    ap.add_argument('--dump-raw', dest='dump_raw', action='store_true')  # RETENTION: ham claims+artifacts (redakteli)
    ap.add_argument('--extra')  # (P0-1b) orkestratör DETERMİNİSTİK prob artefaktları (JSON {artifacts:[...]}) → merge
    a = ap.parse_args()
    if a.input:
        claims, artifacts, meta = load_from_json(a.input)
    elif a.flow:
        claims, artifacts, meta = load_from_pg(a.flow)
    else:
        print("hata: --flow <id> ya da --input <json> gerekli", file=sys.stderr)
        sys.exit(2)

    # (P0-1b HARD-GATE) Orkestratörün kampanya SONRASI çalıştırdığı deterministik checklist probları
    # (STEP2 SQLi, STEP3 2. yansıma) gerçek istek/yanıt olarak buraya eklenir — ajanın erken durması
    # checklist kapsamını DÜŞÜREMEZ. Bunlar da normal terminal artefaktı gibi sınıflanır (aynı kanıt barı).
    if a.extra:
        try:
            with open(a.extra) as fh:
                ex = json.load(fh)
            for art in (ex.get('artifacts') or []):
                art.setdefault('kind', 'terminal')
                if 'id' not in art:
                    art['id'] = f"probe#{len(artifacts) + 1}"
                artifacts.append(art)
        except Exception as e:  # best-effort — merge başarısızsa koşuyu bozma
            print(f"uyarı: --extra okunamadı ({e})", file=sys.stderr)

    thost = a.target or str(meta.get('target', '') or '')
    tip = a.target_ip or str(meta.get('targetIp', '') or '')

    # ——— RETENTION: --dump-raw → binder'ın okuduğu HAM claims+artifacts (redakteli) JSON ———
    # Teardown droplet'i imha ETMEDEN ÖNCE bu job'a saklanır → (1) canlı/sonrası TRANSKRİPT render,
    # (2) offline RE-BIND (yeni koşu olmadan binder mantığını tekrar uygula). Secret'lar redact() ile maskeli.
    if a.dump_raw:
        meta2 = dict(meta); meta2['target'] = thost; meta2['targetIp'] = tip
        def _r(s, n): return redact(str(s or ''))[:n]
        dumped = {
            'meta': meta2,
            'claims': [{'id': c.get('id'), 'title': _r(c.get('title'), 200), 'text': _r(c.get('text'), 4000)} for c in claims],
            'artifacts': [{'id': art['id'], 'kind': art.get('kind'), 'command': _r(art.get('command'), 800),
                           'rawText': _r(art.get('rawText'), 6000)} for art in artifacts],
        }
        print(json.dumps(dumped, ensure_ascii=False))
        return

    # ——— TEŞHİS: --trace → her artefakt + her iddia kararı satır satır (bir daha kör kalma) ———
    if a.trace:
        def cat_of(c): return detect_category(c.get('text', '') + ' ' + c.get('title', ''))
        fnd, filtered = classify(claims, artifacts, thost, tip)
        used = {f['evidence'].get('artifactRef') for f in fnd if f.get('evidence')}
        print(json.dumps({'phase': 'artifacts', 'count': len(artifacts)}, ensure_ascii=False))
        for art in artifacts:
            print(json.dumps({'artifact_id': art['id'], 'kaynak': art.get('kind'),
                              'kanit_mi': artifact_is_evidence(art),   # yalnız terminal=gerçek istek/yanıt
                              'ham_ozet': (art.get('command', '')[:60] + ' | ' + art.get('rawText', '')[:140]),
                              'kanit_olarak_kullanildi': art['id'] in used}, ensure_ascii=False))
        print(json.dumps({'phase': 'claims', 'count': len(claims), 'filtered_meta': filtered}, ensure_ascii=False))
        for c in claims:
            fc = is_finding_claim(c)
            print(json.dumps({'claim_id': c.get('id'), 'kategori': cat_of(c),
                              'bulgu_adayi': fc, 'neden': ('gerçek güvenlik iddiası' if fc else 'plan/meta → filtrelendi (rapora girmez)')},
                             ensure_ascii=False))
        print(json.dumps({'phase': 'findings', 'count': len(fnd),
                          'kanitli': sum(f['tier'] == 'KANITLI' for f in fnd),
                          'belirsiz': sum(f['tier'] == 'BELIRSIZ' for f in fnd),
                          'hayalet': sum(f['tier'] == 'HAYALET' for f in fnd)}, ensure_ascii=False))
        return

    findings, filtered = classify(claims, artifacts, thost, tip)
    kan = [f for f in findings if f['tier'] == 'KANITLI']
    bel = [f for f in findings if f['tier'] == 'BELIRSIZ']
    hay = [f for f in findings if f['tier'] == 'HAYALET']
    overall = max((SEV_ORDER[f['severity']] for f in kan), default=0)
    overall_label = next((k for k, v in SEV_ORDER.items() if v == overall), 'temiz')

    # HAYALET reason-code kırılımı (panelde "hayalet nedenleri" — bir daha kör kalmayalım).
    def reason_code(f):
        r = f.get('reason', '').lower()
        if 'provenance' in r: return 'off-target'
        if 'sıfır iz' in r or 'artefakt yok' in r: return 'no-evidence'
        if 'imza yok' in r or 'imza bulun' in r: return 'weak-signature'
        return 'other'
    elim_reasons = {}
    for f in hay:
        rc = reason_code(f); elim_reasons[rc] = elim_reasons.get(rc, 0) + 1
    if filtered:
        elim_reasons['filtered-meta'] = filtered   # plan/araştırma/tamamlama gürültüsü (bulgu değil, rapora girmedi)

    out = {
        'meta': meta, 'artifactCount': len(artifacts), 'claimCount': len(claims),
        'summary': {'kanitli': len(kan), 'belirsiz': len(bel), 'hayalet': len(hay)},
        'filteredMeta': filtered,            # "bulgu mu?" filtresiyle elenen plan/meta iddia sayısı
        'eliminatedReasons': elim_reasons,   # {off-target, no-evidence, weak-signature, filtered-meta}
        'tried': tried_summary(artifacts),   # P0-2 'Pozitif güvence' + P1 exec (gerçek sayaçlar)
        'overallRisk': overall_label,   # YALNIZ kanıtlı bulgulardan; asla şişirilmez
        'findings': findings,
    }
    if a.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return
    print("=" * 74)
    print(f"  KANIT-BAĞLAYICI (ham artefakta bağlı) — artefakt={len(artifacts)} iddia={len(claims)}")
    print(f"  ÖZET: KANITLI={len(kan)} BELİRSİZ={len(bel)} HAYALET={len(hay)}  | genel risk={overall_label}")
    print("=" * 74)
    for f in findings:
        ev = f['evidence']
        print(f"[{f['tier']}] {f['title']}  ({f['category']}/{f['severity']})")
        print(f"      -> {f['reason']}" + (f"  |  {ev['detail']} [{ev['artifactRef']}]" if ev else ""))


if __name__ == '__main__':
    main()
