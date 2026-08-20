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

# ————————————————————— PROVENANCE (hedef-dışı host referansı = elenir) —————————————————————
_FILE_EXT = {'php','json','html','htm','js','css','xml','txt','png','jpg','jpeg','svg','ico','gif',
             'asp','aspx','jsp','do','action','map','woff','woff2','pdf','mp4','webp'}
# Ajanın eğitim-verisinden sızabilen bilinen izole/eğitim hedef adları (hedef değilse YABANCI).
_KNOWN_FOREIGN = ('juiceshop','juice-shop','juice_shop','localhost','127.0.0.1','testfire','vulnweb','example.com')

def foreign_hosts(text, target_host, target_ip):
    text = (text or '').lower(); th = (target_host or '').lower(); ti = (target_ip or '')
    allow = {h for h in {th, 'www.' + th if th else '', ti} if h}
    hosts = set()
    for m in re.finditer(r'https?://([a-z0-9.\-_]+)', text): hosts.add(m.group(1))
    for m in re.finditer(r'\b([a-z0-9\-]{2,}(?:\.[a-z0-9\-]{2,})+)\b', text):
        h = m.group(1)
        if h.split('.')[-1] in _FILE_EXT: continue     # dosya adı (index.php), host değil
        hosts.add(h)
    for name in _KNOWN_FOREIGN:
        if name in text: hosts.add(name)
    return {h for h in hosts if h and h not in allow}


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
        if sig_hit:
            tier, ev, reason = 'KANITLI', sig_hit, 'ham artefakta bağlı deterministik imza'
        elif beh:
            tier, ev, reason = 'KANITLI', beh, 'ham artefakta bağlı davranışsal anomali'
            bound = next((a for a in related if a.get('id') == beh.get('artifactRef')), (related[0] if related else None))
        elif related:
            tier, ev, reason = 'BELIRSIZ', {'artifactRef': related[0].get('id', '?'), 'signature': '', 'detail': 'artefakt var, kesin imza yok'}, 'artefakt var ama deterministik imza yok -> insan-inceleme'
            bound = related[0]
        else:
            tier, ev, reason = 'HAYALET', None, 'iddiayı destekleyen ham artefakt yok (sıfır iz) -> elenir'

        # HAM KANIT İÇERİĞİ (redakte) — rapor gerçek istek/yanıtı gösterebilsin (yalnız referans değil).
        if ev is not None and bound is not None:
            ev['rawExcerpt'] = redact(bound.get('rawText', ''))[:1000]
            ev['command'] = redact(bound.get('command', ''))[:200]

        # PROVENANCE: KANITLI/BELİRSİZ bulgu hedef-DIŞI host referanslıyorsa (ör. juiceshop) → HAYALET.
        # Ajanın eğitim-bilgisi (Juice Shop vb.) hedefe sızamaz; provenance-dışı bulgu rapora GİRMEZ.
        if tier in ('KANITLI', 'BELIRSIZ'):
            probe = ' '.join([c.get('title', ''), c.get('text', ''), (ev or {}).get('detail', ''),
                              (bound or {}).get('command', ''), (bound or {}).get('rawText', '')])
            fh = foreign_hosts(probe, target_host, target_ip)
            if fh:
                tier, ev = 'HAYALET', None
                reason = f"provenance-dışı: hedef ({target_host or '?'}) yerine yabancı host ({', '.join(sorted(fh))[:60]}) → elenir"

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
    return claims, artifacts, {'flowId': flow_id}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--flow')
    ap.add_argument('--input')
    ap.add_argument('--target', default='')       # PINNED hedef host (provenance kuralı)
    ap.add_argument('--target-ip', dest='target_ip', default='')
    ap.add_argument('--json', action='store_true')
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
    findings = classify(claims, artifacts, thost, tip)
    kan = [f for f in findings if f['tier'] == 'KANITLI']
    bel = [f for f in findings if f['tier'] == 'BELIRSIZ']
    hay = [f for f in findings if f['tier'] == 'HAYALET']
    overall = max((SEV_ORDER[f['severity']] for f in kan), default=0)
    overall_label = next((k for k, v in SEV_ORDER.items() if v == overall), 'temiz')
    out = {
        'meta': meta, 'artifactCount': len(artifacts), 'claimCount': len(claims),
        'summary': {'kanitli': len(kan), 'belirsiz': len(bel), 'hayalet': len(hay)},
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
