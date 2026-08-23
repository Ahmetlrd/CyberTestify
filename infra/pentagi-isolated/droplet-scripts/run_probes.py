#!/usr/bin/env python3
"""
(P0-1b HARD-GATE) Deterministik checklist prob motoru — LLM YOK.

Orkestratör, ajan kampanyası bittikten SONRA bunu droplet'te çalıştırır. Amaç: ajanın erken
durması (ör. STEP1 XSS bulunca durup STEP2 SQLi / STEP3 2. yansımayı hiç denememesi) checklist
kapsamını DÜŞÜREMESİN. Burada üretilen istek/yanıt çiftleri binder'a `--extra` ile verilir ve
NORMAL terminal artefaktı gibi (aynı kanıt barı: HTTP 2xx + gövdede imza/marker) sınıflanır.

Girdi: --plan <json> = {"probes":[{"path":"/x","param":"q","payload":"...","family":"sqli|xss"}...]}
Çıktı: --out <json>  = {"artifacts":[{"id","kind":"terminal","command","rawText"}...]}

Hedefe YALNIZ pinlenen IP'ye --resolve ile bağlanır (orkestratörün ajana verdiği aynı disiplin);
domain yeniden çözülmez. Bu betik BİR SALDIRI DEĞİL — checklist'in deterministik, kanıta-bağlı
tamamlanmasını garanti eder; bulgu yalnız binder gerçek imza görürse çıkar (yoksa "denendi, imza yok").
"""
import sys, json, argparse, subprocess, re


def run(cmd):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=45)
        return ((p.stdout or '') + (p.stderr or ''))[:20000]
    except subprocess.TimeoutExpired:
        return 'PROBE_TIMEOUT (45s)'
    except Exception as e:  # betik asla patlamamalı — best-effort
        return f'PROBE_ERROR: {e}'


def _http_body(raw):
    """curl -i çıktısından (durum+başlık+gövde) gövdeyi ayır (son boş satırdan sonrası)."""
    parts = re.split(r'\r?\n\r?\n', raw, maxsplit=1)
    return parts[1] if len(parts) == 2 else raw


def parse_login_form(html, page_path):
    """(P0-8) GERÇEK login formunu HTML'den ayrıştır: parola alanı İÇEREN <form>'u bul, action + alan
    adlarını çıkar (deterministik, salt-okunur DOM keşfi — LLM yok). Bulunamazsa None."""
    for m in re.finditer(r'<form\b([^>]*)>(.*?)</form>', html, re.I | re.S):
        attrs, inner = m.group(1), m.group(2)
        if not re.search(r'<input\b[^>]*type\s*=\s*["\']?password', inner, re.I):
            continue  # parola alanı yoksa login formu değil
        am = re.search(r'action\s*=\s*["\']?([^"\'\s>]*)', attrs, re.I)
        action = (am.group(1) if am and am.group(1) else page_path) or page_path
        fields = []
        for im in re.finditer(r'<input\b([^>]*)>', inner, re.I):
            ia = im.group(1)
            tm = re.search(r'type\s*=\s*["\']?([a-z]+)', ia, re.I)
            itype = (tm.group(1).lower() if tm else 'text')
            if itype in ('submit', 'button', 'image', 'reset', 'checkbox', 'radio', 'file'):
                continue
            nm = re.search(r'name\s*=\s*["\']?([^"\'\s>]+)', ia, re.I)
            if nm:
                fields.append(nm.group(1))
        if fields:
            return action, fields
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--plan', required=True)
    ap.add_argument('--target', required=True)
    ap.add_argument('--target-ip', dest='ip', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()

    try:
        plan = json.load(open(a.plan))
    except Exception as e:
        print(f'PLAN_READ_ERROR: {e}', file=sys.stderr)
        json.dump({'artifacts': []}, open(a.out, 'w'))
        return

    arts = []
    for i, e in enumerate(plan.get('probes', [])):
        fam = e.get('family', '')
        payload = e.get('payload', '')
        if fam == 'login_sqli':
            # (P0-8) LOGIN FORMU SQLi: aday login path'lerini GET'le, parola-alanlı formu bul, action'a
            # keşfedilen alanlara SQLi payload'ı ile POST at. "Arama kutusuna tırnak" login testi SAYILMAZ.
            done = False
            for path in (e.get('candidates') or []):
                getcmd = f'curl -sk -i --resolve {a.target}:443:{a.ip} --resolve {a.target}:80:{a.ip} "https://{a.target}{path}"'
                getraw = run(getcmd)
                form = parse_login_form(_http_body(getraw), path)
                if not form:
                    continue
                action, fields = form
                if action.startswith('http'):
                    mp = re.search(r'https?://[^/]+(/[^\s"\']*)', action)
                    action = mp.group(1) if mp else path
                elif not action.startswith('/'):
                    action = '/' + action
                data = ' '.join(f'--data-urlencode "{n}={payload}"' for n in fields[:8])
                postcmd = f'curl -sk -i -X POST --resolve {a.target}:443:{a.ip} "https://{a.target}{action}" {data}'
                raw = run(postcmd)
                arts.append({'id': f'probe#{i + 1}', 'kind': 'terminal', 'command': postcmd, 'rawText': raw})
                done = True
                break
            if not done:
                # Login formu keşfedilemedi — DÜRÜST kayıt (sahte "denendi" demeyiz; sadece keşif izini bırak).
                tried = ', '.join(e.get('candidates') or [])
                arts.append({'id': f'probe#{i + 1}', 'kind': 'note',
                             'command': f'login-form-discovery {tried}',
                             'rawText': f'LOGIN_FORM_NOT_FOUND: parola-alanlı form aday path(ler)de bulunamadı ({tried})'})
            continue
        path = e.get('path') or '/'
        param = e.get('param')
        # Ajanın kullandığı aynı curl disiplini: -sk -i (durum+başlık), --resolve ile YALNIZ pinlenen IP.
        base = f'curl -sk -i -G --resolve {a.target}:443:{a.ip} "https://{a.target}{path}"'
        cmd = base + (f' --data-urlencode "{param}={payload}"' if param else '')
        raw = run(cmd)
        arts.append({'id': f'probe#{i + 1}', 'kind': 'terminal', 'command': cmd, 'rawText': raw})

    try:
        json.dump({'artifacts': arts}, open(a.out, 'w'), ensure_ascii=False)
    except Exception as e:
        print(f'OUT_WRITE_ERROR: {e}', file=sys.stderr)
        return
    print(f'PROBES_DONE {len(arts)}')


if __name__ == '__main__':
    main()
