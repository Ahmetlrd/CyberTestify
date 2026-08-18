#!/usr/bin/env python3
# (PentAGI Aşama 2) KANIT-BAĞLAMA HARNESS — bounded Sonnet ajanı localhost Juice Shop'a karşı;
# her tool-call ham istek/yanıt artefakta bağlanır; 3-katman sınıflama: KANITLI / BELİRSİZ / HAYALET.
# READ-ONLY (yalnız GET localhost:3000). Anahtar env'den; diske yazılmaz.
import os, json, urllib.request, urllib.error, hashlib, re, time, sys

TARGET = "http://127.0.0.1:3000"
MODEL = "claude-sonnet-5"
KEY = os.environ.get("LLM_API_KEY", "")
AUDIT_DIR = "/opt/pentagi-run/audit"; ART_DIR = "/opt/pentagi-run/artifacts"
os.makedirs(AUDIT_DIR, exist_ok=True); os.makedirs(ART_DIR, exist_ok=True)
RUN = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
audit = open(f"{AUDIT_DIR}/run-{RUN}.log", "w")
def log(x): audit.write(f"{time.strftime('%FT%TZ',time.gmtime())} {x}\n"); audit.flush()

ARTIFACTS = {}   # id -> {request, response{status,body}}
def http_probe(method, path, query=None):
    # SÜTUN 0 + izolasyon: YALNIZ localhost, YALNIZ GET (read-only)
    if method.upper() != "GET": return {"error": "yalnız GET izinli (read-only)"}
    url = TARGET + path + (("?" + query) if query else "")
    if not url.startswith(TARGET): return {"error": "yalnız localhost:3000 hedeflenebilir"}
    aid = "A" + hashlib.sha1(f"{url}{time.time()}".encode()).hexdigest()[:10]
    req = {"method": "GET", "url": url}
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=10)
        body = r.read(60000).decode("utf-8", "replace"); status = r.getcode()
    except urllib.error.HTTPError as e:
        body = e.read(60000).decode("utf-8", "replace"); status = e.code
    except Exception as e:
        body = f"(bağlantı hatası: {e})"; status = 0
    ARTIFACTS[aid] = {"request": req, "response": {"status": status, "body": body}}
    json.dump(ARTIFACTS[aid], open(f"{ART_DIR}/{aid}.json", "w"))
    log(f"PROBE {aid} GET {url} -> {status} ({len(body)}b)")
    return {"artifact_id": aid, "status": status, "body_snippet": body[:1200]}

REPORTS = []
def report_finding(**kw):
    REPORTS.append(kw); log(f"AGENT-REPORT {kw.get('vuln_class')} @ {kw.get('endpoint')} art={kw.get('evidence_artifact_id')}")
    return {"ack": True}

# ---- 3-KATMAN KANIT-BAĞLAMA (backend 'kanıt var mı' mantığı; ajanın iddiası DEĞİL) ----
SIG = {
  "sqli": re.compile(r"SQLITE_ERROR|SQL syntax|syntax error|unrecognized token|SQLITE_|near \"", re.I),
  "path_traversal": re.compile(r"root:x:0:0:|\[fonts\]"),
  "lfi": re.compile(r"root:x:0:0:|\[fonts\]"),
  "info_disclosure": re.compile(r"SQLITE_ERROR|stack trace|\n    at |/juice-shop/|ENOENT|EACCES", re.I),
  "xss": re.compile(r"<script>ct[0-9]+</script>|ctxss[0-9]+", re.I),
}
def classify(f):
    aid = f.get("evidence_artifact_id"); vc = (f.get("vuln_class") or "").lower()
    art = ARTIFACTS.get(aid)
    if not art:  # sıfır iz / uydurma artefakt
        return ("HAYALET", "referans verilen kanıt artefaktı YOK (sıfır iz) — elenir", None)
    body = art["response"]["body"]; sig = SIG.get(vc)
    if sig and sig.search(body):
        m = sig.search(body)
        return ("KANITLI", f"artefakt {aid} yanıtında deterministik imza eşleşti: '{m.group(0)[:40]}'", aid)
    return ("BELİRSİZ", f"artefakt {aid} var ama {vc} için deterministik imza YOK — silinmez, insan-inceleme katmanına", aid)

TOOLS = [
  {"name":"http_probe","description":"localhost:3000 (Juice Shop) hedefine GÜVENLİ read-only GET isteği gönder; ham yanıtı artefakt olarak kaydeder.","input_schema":{"type":"object","properties":{"method":{"type":"string"},"path":{"type":"string"},"query":{"type":"string"}},"required":["method","path"]}},
  {"name":"report_finding","description":"Bir zafiyet bulgusu bildir. evidence_artifact_id: bulguyu KANITLAYAN http_probe artefakt id'si (uydurma).","input_schema":{"type":"object","properties":{"title":{"type":"string"},"vuln_class":{"type":"string","description":"sqli|xss|path_traversal|lfi|info_disclosure|other"},"endpoint":{"type":"string"},"evidence_artifact_id":{"type":"string"},"rationale":{"type":"string"}},"required":["title","vuln_class","endpoint","evidence_artifact_id"]}},
]
SYS = ("Sen izole bir test ortamında localhost:3000 (OWASP Juice Shop) hedefini inceleyen bir güvenlik ajanısın. "
       "YALNIZ http_probe ile GÜVENLİ read-only GET istekleri gönder (veri değiştirme/yükleme YOK). "
       "Bir zafiyet bulursan report_finding çağır ve evidence_artifact_id'yi o bulguyu KANITLAYAN http_probe artefaktının id'siyle DOLDUR. "
       "İpucu: ürün arama uç noktası (/rest/products/search?q=) SQL enjeksiyonuna açık olabilir; tek tırnak ile hata imzası ara. "
       "Kanıtlayamadığını rapor etme. En fazla 8 prob. Bitince kısa özet yaz.")

def anthropic(messages):
    payload = {"model":MODEL,"max_tokens":1024,"system":SYS,"tools":TOOLS,"messages":messages}
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=json.dumps(payload).encode(),
        headers={"x-api-key":KEY,"anthropic-version":"2023-06-01","content-type":"application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=90) as r: return json.load(r)

def run_agent():
    messages=[{"role":"user","content":"Hedefi incele ve kanıtlayabildiğin zafiyetleri report_finding ile bildir."}]
    for step in range(5):
        resp = anthropic(messages)
        stop = resp.get("stop_reason"); blocks = resp.get("content",[])
        messages.append({"role":"assistant","content":blocks})
        tr=[]
        for b in blocks:
            if b.get("type")=="tool_use":
                name=b["name"]; inp=b.get("input",{})
                out = http_probe(inp.get("method","GET"),inp.get("path","/"),inp.get("query")) if name=="http_probe" else report_finding(**inp)
                tr.append({"type":"tool_result","tool_use_id":b["id"],"content":json.dumps(out)[:4000]})
            elif b.get("type")=="text": log(f"AGENT-TEXT {b['text'][:200]}")
        if not tr: break
        messages.append({"role":"user","content":tr})
    return

print("== KANIT-BAĞLAMA HARNESS başlıyor (Sonnet, localhost Juice Shop, read-only) ==")
try: run_agent()
except Exception as e: print("ajan hata:", str(e)[:200]); log(f"AGENT-ERR {e}")

# --- 3 KONTROLLÜ vaka: backend'in kanıt-bağlamasını DETERMİNİSTİK ispatlar (ajan şansına bağlı değil) ---
# (KANITLI) GERÇEK SQLi: backend uca kendisi güvenli GET atar, yanıttaki SQL hata imzasına bağlar
prov = http_probe("GET","/rest/products/search","q=test%27")
REPORTS.append({"title":"[KONTROL] SQL Enjeksiyonu — ürün arama q parametresi","vuln_class":"sqli","endpoint":"/rest/products/search?q=","evidence_artifact_id":prov.get("artifact_id"),"rationale":"backend GET ile SQL hata imzası yakaladı"})
# (BELİRSİZ) gerçek uç ama vuln imzası yok -> insan-inceleme
gray = http_probe("GET","/rest/products","")
REPORTS.append({"title":"[KONTROL] Belirsiz — ürün listesi ifşası","vuln_class":"info_disclosure","endpoint":"/rest/products","evidence_artifact_id":gray.get("artifact_id"),"rationale":"iz var, net ispat yok"})
# (HAYALET) uydurma bulgu, sıfır iz -> elenir
REPORTS.append({"title":"[KONTROL] Uydurma RCE (halüsinasyon)","vuln_class":"rce","endpoint":"/rest/admin","evidence_artifact_id":"A-NONEXISTENT-999","rationale":"sıfır kanıt"})

print("\n== 3-KATMAN KANIT-BAĞLAMA SONUÇLARI ==")
out={"KANITLI":[],"BELİRSİZ":[],"HAYALET":[]}
for f in REPORTS:
    tier,reason,aid = classify(f)
    out[tier].append({"title":f.get("title"),"vuln_class":f.get("vuln_class"),"endpoint":f.get("endpoint"),"artifact":aid,"reason":reason})
    log(f"CLASSIFY {tier} :: {f.get('title')} :: {reason}")
for tier in ["KANITLI","BELİRSİZ","HAYALET"]:
    print(f"\n[{tier}] ({len(out[tier])})")
    for r in out[tier]:
        print(f"  • {r['title']} ({r['vuln_class']}) @ {r['endpoint']}")
        print(f"      → {r['reason']}")
        if r['artifact'] and tier=='KANITLI':
            b=ARTIFACTS[r['artifact']]['response']['body']; m=re.search(r'SQLITE_ERROR|SQL syntax|root:x:0:0:',b)
            print(f"      → BAĞLI HAM KANIT (artefakt {r['artifact']}): status={ARTIFACTS[r['artifact']]['response']['status']}, imza='{m.group(0) if m else ''}'")
print("\n== ÖZET ==")
print(f"  KANITLI(bulgu)={len(out['KANITLI'])}  BELİRSİZ(insan-inceleme)={len(out['BELİRSİZ'])}  HAYALET(elendi)={len(out['HAYALET'])}")
print(f"  toplam artefakt={len(ARTIFACTS)}  audit={AUDIT_DIR}/run-{RUN}.log")
json.dump(out, open(f"{AUDIT_DIR}/result-{RUN}.json","w"), ensure_ascii=False, indent=2)
audit.close()
