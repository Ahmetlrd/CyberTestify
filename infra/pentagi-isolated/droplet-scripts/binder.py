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
            'ssrf': 'orta', 'info_disclosure': 'orta', 'xss': 'orta', 'open_redirect': 'düşük', 'bilinmeyen': 'düşük'}
SEV_ORDER = {'kritik': 4, 'yüksek': 3, 'orta': 2, 'düşük': 1, 'temiz': 0}


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
        cmd = a.get('command', '') + ' ' + a.get('rawText', '')
        raw = a.get('rawText', '')
        for m in re.finditer(r'(zqx[a-z0-9]*marker[a-z0-9]*|<script\b[^>]*>|<img\b[^>]*>|["\'>]<[a-z]{1,10}[ >/])', cmd, re.I):
            marker = m.group(0)
            if marker in raw:
                idx = raw.find(marker)
                around = raw[max(0, idx - 4):idx + len(marker) + 4]
                if '&lt;' not in around and '&gt;' not in around and '%3c' not in around.lower():
                    return {'artifactRef': a.get('id', '?'), 'signature': 'reflected-unencoded',
                            'detail': f"payload {marker[:34]!r} yanıt gövdesinde ENCODE EDİLMEDEN yansıdı → reflected XSS"}
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


def classify(claims, artifacts, target_host='', target_ip=''):
    findings = []
    for c in claims:
        cat = detect_category(c.get('text', '') + ' ' + c.get('title', ''))
        related = [a for a in artifacts if relates(a, c, cat)]
        sig_re = SIG.get(cat)
        sig_hit = None; bound = None
        if sig_re:
            # İMZA yalnız İLİŞKİLİ ham artefaktta aranır — ilişkisiz artefaktın imzasına bağlamak sahte-KANITLI.
            for a in related:
                m = re.search(sig_re, a.get('rawText', ''), re.I)
                if m:
                    sig_hit = {'artifactRef': a.get('id', '?'), 'signature': m.group(0)[:60],
                               'detail': f"ham artefaktta deterministik imza: {m.group(0)[:60]!r}"}
                    bound = a; break
        beh = behavioral_sqli(cat, related, artifacts)
        rxss = reflected_xss(cat, related)
        if sig_hit:
            tier, ev, reason = 'KANITLI', sig_hit, 'ham artefakta bağlı deterministik imza'
        elif beh:
            tier, ev, reason = 'KANITLI', beh, 'ham artefakta bağlı davranışsal anomali'
            bound = next((a for a in related if a.get('id') == beh.get('artifactRef')), (related[0] if related else None))
        elif rxss:
            tier, ev, reason = 'KANITLI', rxss, 'reflected XSS — payload yanıtta ENCODE EDİLMEDEN yansıdı'
            bound = next((a for a in related if a.get('id') == rxss.get('artifactRef')), (related[0] if related else None))
        elif related:
            tier, ev, reason = 'BELIRSIZ', {'artifactRef': related[0].get('id', '?'), 'signature': '', 'detail': 'artefakt var, kesin imza yok'}, 'artefakt var ama deterministik imza yok -> insan-inceleme'
            bound = related[0]
        else:
            tier, ev, reason = 'HAYALET', None, 'iddiayı destekleyen ham artefakt yok (sıfır iz) -> elenir'

        # HAM KANIT İÇERİĞİ (redakte) — rapor gerçek istek/yanıtı gösterebilsin (yalnız referans değil).
        if ev is not None and bound is not None:
            ev['rawExcerpt'] = redact(bound.get('rawText', ''))[:1000]
            ev['command'] = redact(bound.get('command', ''))[:200]

        # PROVENANCE: İSTEĞİN ATILDIĞI host hedef-DIŞI ise (ör. istek juiceshop'a atılmış) → HAYALET.
        # Yalnız isteğin gönderildiği host'a bakar; yanıt GÖVDESİNDEKİ linkler (altoromutual.com) ya da
        # --resolve'un IP kısmı (hedefin pinlenen IP'si) provenance'ı ETKİLEMEZ — onlar hedefin içeriği.
        if tier in ('KANITLI', 'BELIRSIZ'):
            off = off_target_request(bound, c, target_host, target_ip)
            if off:
                tier, ev = 'HAYALET', None
                reason = f"provenance-dışı: istek hedef ({target_host or '?'}) yerine {off}'a atıldı → elenir"

        findings.append({
            'title': c.get('title') or (c.get('text', '')[:80]),
            'category': cat, 'endpoint': extract_endpoint(c.get('text', '')),
            'severity': SEVERITY.get(cat, 'düşük'),
            'tier': tier, 'evidence': ev, 'reason': reason,
        })
    return findings


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
    a = ap.parse_args()
    if a.input:
        claims, artifacts, meta = load_from_json(a.input)
    elif a.flow:
        claims, artifacts, meta = load_from_pg(a.flow)
    else:
        print("hata: --flow <id> ya da --input <json> gerekli", file=sys.stderr)
        sys.exit(2)

    thost = a.target or str(meta.get('target', '') or '')
    tip = a.target_ip or str(meta.get('targetIp', '') or '')

    # ——— TEŞHİS: --trace → her artefakt + her iddia kararı satır satır (bir daha kör kalma) ———
    if a.trace:
        def cat_of(c): return detect_category(c.get('text', '') + ' ' + c.get('title', ''))
        used = set()
        fnd = classify(claims, artifacts, thost, tip)
        for f in fnd:
            if f.get('evidence'): used.add(f['evidence'].get('artifactRef'))
        print(json.dumps({'phase': 'artifacts', 'count': len(artifacts)}, ensure_ascii=False))
        for art in artifacts:
            print(json.dumps({'artifact_id': art['id'], 'kaynak': art.get('kind'),
                              'ham_ozet': (art.get('command', '')[:60] + ' | ' + art.get('rawText', '')[:140]),
                              'kanit_olarak_kullanildi': art['id'] in used}, ensure_ascii=False))
        print(json.dumps({'phase': 'claims', 'count': len(claims)}, ensure_ascii=False))
        for c, f in zip(claims, fnd):
            cat = cat_of(c)
            rel = [x['id'] for x in artifacts if relates(x, c, cat)]
            print(json.dumps({'claim_id': c.get('id'), 'kategori': cat, 'iliskili_artefakt': rel[:6],
                              'iliskili_sayi': len(rel), 'sinif': f['tier'], 'neden': f['reason'][:100]}, ensure_ascii=False))
        return

    findings = classify(claims, artifacts, thost, tip)
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

    out = {
        'meta': meta, 'artifactCount': len(artifacts), 'claimCount': len(claims),
        'summary': {'kanitli': len(kan), 'belirsiz': len(bel), 'hayalet': len(hay)},
        'eliminatedReasons': elim_reasons,   # {off-target: n, no-evidence: n, weak-signature: n}
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
