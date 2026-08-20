#!/usr/bin/env python3
# Bounded PentAGI kampanya + SERT cap. Cap tetiğinde HARD-STOP SIRASI:
#   1) Anthropic egress KES (ağ-katmanı; backend ajan döngüsü worker-kill'e RAĞMEN
#      LLM harcamaya devam edebilir -> tek kesin durdurma budur)
#   2) finishFlow(flowId) [doğru imza: skaler ResultType]
#   3) worker konteynerlerini öldür (temizlik)
# Caps env ile: CAP_SEC / CAP_CALLS / CAP_COST  (ilk gelen HARD STOP)
import urllib.request, ssl, json, time, subprocess, sys, os, re
TOK=open("/opt/pentagi-run/api_token").read().strip()
CTX=ssl.create_default_context(); CTX.check_hostname=False; CTX.verify_mode=ssl.CERT_NONE
URL="https://localhost:8443/api/v1/graphql"
CORE={"pentagi","pgvector","scraper","juiceshop"}
CAP_SEC=int(os.environ.get("CAP_SEC","300"))
CAP_CALLS=int(os.environ.get("CAP_CALLS","15"))
CAP_COST=float(os.environ.get("CAP_COST","1.00"))
PROMPT=os.environ.get("CAMPAIGN_PROMPT",
    "You are testing an AUTHORIZED, isolated test instance. Target: http://juiceshop:3000 . "
    "Do a MINIMAL, quick check: focus ONLY on /rest/products/search?q= for SQL injection. "
    "Send at most a few HTTP requests, confirm with concrete evidence, then STOP and report.")

def gql(q,v=None):
    b={"query":q}
    if v: b["variables"]=v
    req=urllib.request.Request(URL,data=json.dumps(b).encode(),
        headers={"Authorization":"Bearer "+TOK,"content-type":"application/json"},method="POST")
    return json.loads(urllib.request.urlopen(req,context=CTX,timeout=25).read().decode())
def psql(sql):
    return subprocess.run(["docker","exec","pgvector","psql","-U","postgres","-d","pentagidb","-tAc",sql],
                          capture_output=True,text=True).stdout.strip()

def cut_anthropic_egress():
    """Anthropic'i KESİN kes: IP için EN ÜSTE DROP ekle (ESTABLISHED kuralının ÜSTÜNDE -> mevcut
    keep-alive akışları da anında ölür) + 443-ACCEPT izinlerini temizle."""
    ips=set()
    out=subprocess.run(["getent","ahostsv4","api.anthropic.com"],capture_output=True,text=True).stdout
    ips |= {l.split()[0] for l in out.splitlines() if l.split()}
    rules=subprocess.run(["iptables","-S","DOCKER-USER"],capture_output=True,text=True).stdout.splitlines()
    for r in rules:
        if "--dport 443" in r and "-j ACCEPT" in r:
            m=re.search(r"-d (\d+\.\d+\.\d+\.\d+)",r)
            if m: ips.add(m.group(1))
    for ip in ips:  # top-priority DROP: ESTABLISHED-allow'un ÜSTÜNE
        subprocess.run(["iptables","-I","DOCKER-USER","1","-d",ip,"-j","DROP"],capture_output=True,text=True)
    n=0
    for r in rules:  # eski ACCEPT izinlerini temizle
        if "--dport 443" in r and "-j ACCEPT" in r:
            subprocess.run(("iptables "+r.replace("-A ","-D ",1)).split(),capture_output=True,text=True); n+=1
    return len(ips)
def anthropic_reachable():
    # curl'ü DOĞRUDAN CMD olarak çalıştır (login-shell banner'ı stdout'u kirletmesin -> yanlış-pozitif olmasın)
    r=subprocess.run(["docker","run","--rm","--network","pentagi-network","vxcontrol/kali-linux",
        "curl","-s","-o","/dev/null","-w","%{http_code}","--max-time","8","https://api.anthropic.com/"],
        capture_output=True,text=True)
    code=r.stdout.strip()
    return r.returncode==0 and code.isdigit() and code!="000"
def kill_workers():
    for n in subprocess.run(["docker","ps","--format","{{.Names}}"],capture_output=True,text=True).stdout.split():
        if n not in CORE:
            subprocess.run(["docker","kill",n],capture_output=True,text=True); print(f"  kill-switch: {n} durduruldu",flush=True)

def hard_stop(fid,reason):
    print(f"== HARD STOP: {reason} ==",flush=True)
    nip=cut_anthropic_egress(); time.sleep(2); print(f"  [1] Anthropic egress KESİLDİ (top-DROP {nip} IP; ESTABLISHED dahil) -> LLM harcaması İMKANSIZ",flush=True)
    print(f"      doğrula: konteynerden Anthropic erişimi = {'AÇIK ⚠' if anthropic_reachable() else 'BLOCKED ✓'}",flush=True)
    try: print("  [2] finishFlow ->",json.dumps(gql("mutation($id:ID!){finishFlow(flowId:$id)}",{"id":str(fid)})),flush=True)
    except Exception as e: print("  [2] finishFlow ERR",str(e)[:100],flush=True)
    print("  [3] worker temizliği:",flush=True); kill_workers()

def wait_api_ready(max_s=180):
    # PentAGI GraphQL DİNLEMEYE + token GEÇERLİ olana kadar bekle (compose up hemen döner; server geç kalkar).
    start=time.time(); last=""
    while time.time()-start < max_s:
        try:
            r=gql("{__typename}")
            if isinstance(r,dict) and r.get("data"): return True
            last=str(r)[:120]
        except Exception as e:
            last=str(e)[:120]
        time.sleep(4)
    print(f"== API hazır olmadı ({max_s}s): {last} ==",flush=True); return False

def main():
    print(f"== PentAGI GraphQL API hazırlığı bekleniyor ==",flush=True)
    if not wait_api_ready():
        sys.exit(1)
    print(f"== createFlow (anthropic) caps: {CAP_SEC}s/{CAP_CALLS}calls/${CAP_COST} ==",flush=True)
    r=gql("mutation($p:String!,$i:String!){createFlow(modelProvider:$p,input:$i){id status title}}",
          {"p":"anthropic","i":PROMPT})
    if "errors" in r: print("createFlow ERROR:",json.dumps(r["errors"])[:300]); sys.exit(1)
    fl=r["data"]["createFlow"]; FID=str(fl["id"]); open("/opt/pentagi-run/flow_id","w").write(FID)
    print(f"  flow_id={FID} status={fl['status']} title={fl.get('title')!r}",flush=True)
    t0=time.time(); reason=None
    while True:
        el=int(time.time()-t0)
        calls=int(psql(f"SELECT count(*) FROM msgchains WHERE flow_id={FID};") or 0)
        cost=float(psql(f"SELECT COALESCE(SUM(usage_cost_in+usage_cost_out),0)::numeric(12,4) FROM msgchains WHERE flow_id={FID};") or 0)
        tcs=int(psql(f"SELECT count(*) FROM toolcalls WHERE flow_id={FID};") or 0)
        print(f"  [t={el}s] llm_calls={calls} tool_calls={tcs} cost=${cost:.4f}",flush=True)
        if el>=CAP_SEC: reason=f"SÜRE cap ({CAP_SEC}s)"; break
        if calls>=CAP_CALLS: reason=f"ÇAĞRI cap ({CAP_CALLS})"; break
        if cost>=CAP_COST: reason=f"MALİYET cap (${CAP_COST})"; break
        stt=psql(f"SELECT status FROM flows WHERE id={FID};")
        # Ajanlar ASYNC başlar: flow 'finished/failed' görünse bile calls==0 ise HENÜZ iş yapmamış
        # olabilir → BEKLE (cap SÜRE sınırı yakalar). Yalnız gerçekten aktivite olduysa (calls>0) bitir.
        if stt in ("finished","failed") and calls>0: reason=f"flow {stt}"; break
        time.sleep(10)
    hard_stop(FID,reason)
    # cap sonrası harcama DONMUŞ mu (sert-durdurma ispatı)
    c1=int(psql(f"SELECT count(*) FROM msgchains WHERE flow_id={FID};") or 0); time.sleep(20)
    c2=int(psql(f"SELECT count(*) FROM msgchains WHERE flow_id={FID};") or 0)
    fcost=psql(f"SELECT COALESCE(SUM(usage_cost_in+usage_cost_out),0)::numeric(10,4) FROM msgchains WHERE flow_id={FID};")
    fst=psql(f"SELECT status FROM flows WHERE id={FID};")
    frozen = "✓ DONDU" if c1==c2 else f"⚠ HÂLÂ ARTIYOR ({c1}->{c2})"
    print(f"== SON: calls={c2} cost=${fcost} flow.status={fst} | cap-sonrası-harcama: {frozen} (neden={reason}) ==",flush=True)
    print(f"== NOT: Anthropic egress kapalı; 3b'de yeni koşu için 'egress-harden-docker.sh' (--no-llm'siz) çalıştır ==",flush=True)

if __name__=="__main__": main()
