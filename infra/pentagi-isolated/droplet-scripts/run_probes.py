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
import sys, json, argparse, subprocess


def run(cmd):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=45)
        return ((p.stdout or '') + (p.stderr or ''))[:20000]
    except subprocess.TimeoutExpired:
        return 'PROBE_TIMEOUT (45s)'
    except Exception as e:  # betik asla patlamamalı — best-effort
        return f'PROBE_ERROR: {e}'


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
        path = e.get('path') or '/'
        param = e.get('param')
        payload = e.get('payload', '')
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
