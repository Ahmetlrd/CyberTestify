import urllib.request, ssl, json, time, subprocess, sys
TOK=open("/opt/pentagi-run/api_token").read().strip()
CTX=ssl.create_default_context(); CTX.check_hostname=False; CTX.verify_mode=ssl.CERT_NONE
URL="https://localhost:8443/api/v1/graphql"
CORE={"pentagi","pgvector","scraper","juiceshop"}
CAP_SEC=300; CAP_CALLS=15; CAP_COST=1.00   # ilk gelen HARD STOP
def gql(q,v=None):
    body={"query":q}; 
    if v: body["variables"]=v
    req=urllib.request.Request(URL,data=json.dumps(body).encode(),
        headers={"Authorization":"Bearer "+TOK,"content-type":"application/json"},method="POST")
    return json.loads(urllib.request.urlopen(req,context=CTX,timeout=25).read().decode())
def psql(sql):
    r=subprocess.run(["docker","exec","pgvector","psql","-U","postgres","-d","pentagidb","-tAc",sql],capture_output=True,text=True)
    return r.stdout.strip()
def kill_workers():
    names=subprocess.run(["docker","ps","--format","{{.Names}}"],capture_output=True,text=True).stdout.split()
    for n in names:
        if n not in CORE:
            subprocess.run(["docker","kill",n],capture_output=True,text=True); print(f"  kill-switch: konteyner {n} durduruldu",flush=True)

PROMPT=("You are testing an AUTHORIZED, isolated test instance. Target: http://juiceshop:3000 . "
        "Do a MINIMAL, quick check: focus ONLY on the product search endpoint /rest/products/search?q= for SQL injection. "
        "Send at most a few HTTP requests to confirm with concrete evidence (error messages / response body). "
        "Do NOT scan broadly, do NOT brute force. Stop right after confirming one or two findings and report them.")

print("== createFlow (anthropic, bounded) ==",flush=True)
r=gql("mutation($p:String!,$i:String!){createFlow(modelProvider:$p,input:$i){id status title}}",{"p":"anthropic","i":PROMPT})
if "errors" in r: print("createFlow ERROR:",json.dumps(r["errors"])[:300]); sys.exit(1)
fl=r["data"]["createFlow"]; FID=str(fl["id"])
print(f"  flow_id={FID} status={fl['status']} title={fl.get('title')!r}",flush=True)
open("/opt/pentagi-run/flow_id","w").write(FID)

t0=time.time(); reason=None
while True:
    el=int(time.time()-t0)
    calls=psql(f"SELECT count(*) FROM msgchains WHERE flow_id={FID};") or "0"
    cost=psql(f"SELECT COALESCE(SUM(usage_cost_in+usage_cost_out),0)::numeric(12,4) FROM msgchains WHERE flow_id={FID};") or "0"
    tcs=psql(f"SELECT count(*) FROM toolcalls WHERE flow_id={FID};") or "0"
    try: st=gql("query($id:ID!){flow(id:$id){status}}",{"id":FID}).get("data",{}).get("flow",{}).get("status","?")
    except Exception: st="?"
    print(f"  [t={el}s] status={st} llm_calls={calls} tool_calls={tcs} cost=${cost}",flush=True)
    c=int(calls or 0); f=float(cost or 0)
    if el>=CAP_SEC: reason=f"SÜRE cap ({CAP_SEC}s)"; break
    if c>=CAP_CALLS: reason=f"ÇAĞRI cap ({CAP_CALLS})"; break
    if f>=CAP_COST: reason=f"MALİYET cap (${CAP_COST})"; break
    if st in ("finished","failed"): reason=f"flow {st}"; break
    time.sleep(15)

print(f"== HARD STOP: {reason} ==",flush=True)
try: print("  stopFlow:",json.dumps(gql("mutation($id:ID!){stopFlow(flowId:$id){id status}}",{"id":FID}))[:160],flush=True)
except Exception as e: print("  stopFlow ERR",str(e)[:100],flush=True)
kill_workers()
fc=psql(f"SELECT count(*) FROM msgchains WHERE flow_id={FID};"); fcost=psql(f"SELECT COALESCE(SUM(usage_cost_in+usage_cost_out),0)::numeric(12,4) FROM msgchains WHERE flow_id={FID};")
ftc=psql(f"SELECT count(*) FROM toolcalls WHERE flow_id={FID};"); ftl=psql(f"SELECT count(*) FROM termlogs WHERE flow_id={FID};")
print(f"== SON: llm_calls={fc} tool_calls={ftc} termlogs={ftl} toplam_maliyet=${fcost} (neden={reason}) ==",flush=True)
