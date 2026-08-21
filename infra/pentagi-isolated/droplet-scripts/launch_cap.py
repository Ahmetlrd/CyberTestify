#!/usr/bin/env python3
# Bounded PentAGI kampanya + SERT cap. Cap tetiğinde HARD-STOP SIRASI:
#   1) Anthropic egress KES (ağ-katmanı; backend ajan döngüsü worker-kill'e RAĞMEN
#      LLM harcamaya devam edebilir -> tek kesin durdurma budur)
#   2) finishFlow(flowId) [doğru imza: skaler ResultType]
#   3) worker konteynerlerini öldür (temizlik)
# Caps env ile: CAP_SEC / CAP_CALLS / CAP_COST  (ilk gelen HARD STOP)
import urllib.request, ssl, json, time, subprocess, sys, os, re, argparse, base64
TOK=open("/opt/pentagi-run/api_token").read().strip()
CTX=ssl.create_default_context(); CTX.check_hostname=False; CTX.verify_mode=ssl.CERT_NONE
URL="https://localhost:8443/api/v1/graphql"
CORE={"pentagi","pgvector","scraper","juiceshop"}

# ——— GÖREV + CAP: ARG'DAN (orchestrator gerçek görevi base64 ile geçirir). ÖNCEDEN CAMPAIGN_PROMPT env
# olarak geçiriliyordu ama runner '#'-argümanlarını atıyordu → env HİÇ ulaşmıyordu → aşağıdaki juiceshop
# default'una düşülüyordu → ajan bir saat PentAGI'nin GÖMÜLÜ juiceshop:3000 örneğini arıyordu (0-kanıtlı).
# ARTIK: görev --prompt-b64 ile REAL arg olarak gelir; juiceshop DEFAULT'U KALDIRILDI (yoksa sesli hata).
_ap=argparse.ArgumentParser()
_ap.add_argument("--prompt-b64",default="")
_ap.add_argument("--cap-sec",type=int,default=int(os.environ.get("CAP_SEC","300")))
_ap.add_argument("--cap-calls",type=int,default=int(os.environ.get("CAP_CALLS","15")))
_ap.add_argument("--cap-cost",type=float,default=float(os.environ.get("CAP_COST","1.00")))
_ap.add_argument("--target",default=os.environ.get("REDTEAM_TARGET",""))
_A,_=_ap.parse_known_args()
CAP_SEC=_A.cap_sec; CAP_CALLS=_A.cap_calls; CAP_COST=_A.cap_cost; TARGET=_A.target.strip()
if _A.prompt_b64:
    PROMPT=base64.b64decode(_A.prompt_b64).decode("utf-8")
elif os.environ.get("CAMPAIGN_PROMPT"):
    PROMPT=os.environ["CAMPAIGN_PROMPT"]
else:
    print("FATAL: görev verilmedi (--prompt-b64/CAMPAIGN_PROMPT yok) — juiceshop default'a DÜŞMEYİ REDDEDİYORUM "
          "(yanlış-hedef koşusu engellendi).",flush=True); sys.exit(3)

def gql(q,v=None):
    b={"query":q}
    if v: b["variables"]=v
    req=urllib.request.Request(URL,data=json.dumps(b).encode(),
        headers={"Authorization":"Bearer "+TOK,"content-type":"application/json"},method="POST")
    return json.loads(urllib.request.urlopen(req,context=CTX,timeout=25).read().decode())
def psql(sql):
    # TIMEOUT: sorgu asılırsa (DB yük/lock) cap döngüsünü BLOKLAMASIN → süre hard-stop'u geciktirmesin.
    try:
        return subprocess.run(["docker","exec","pgvector","psql","-U","postgres","-d","pentagidb","-tAc",sql],
                              capture_output=True,text=True,timeout=15).stdout.strip()
    except Exception:
        return ""

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

def flow_task_text(fid):
    """Flow'un saklanan görev metnini şema-dayanıklı topla (createFlow input'u burada yankılanır)."""
    parts=[]
    for sql in (f"SELECT coalesce(title,'') FROM flows WHERE id={fid}",
                f"SELECT string_agg(coalesce(title,'')||' '||left(coalesce(result,''),400),' ') "
                f"FROM subtasks WHERE task_id IN (SELECT id FROM tasks WHERE flow_id={fid})"):
        try: parts.append(psql(sql) or "")
        except Exception: pass
    return " ".join(parts).lower()

def early_target_gate(fid, target, max_s=75):
    """D2/D3: flow'un görevi GERÇEKTEN hedefi mi hedefliyor? juiceshop görürse ABORT; hedef görürse OK.
    subtask'lar ~30-60s'de oluşur → poll. Hedef hiç görünmezse (belirsiz) koşuyu durdurmayız (yanlış-teardown yok)."""
    th=(target or "").lower(); start=time.time()
    while time.time()-start < max_s:
        txt=flow_task_text(fid)
        if "juiceshop" in txt:
            return False, "ajan juiceshop hedefliyor (createFlow görevi YANLIŞ)"
        if th and th in txt:
            return True, f"hedef '{target}' görevde doğrulandı (juiceshop yok)"
        time.sleep(5)
    return None, f"görev metni {max_s}s'de okunamadı (belirsiz; koşu devam)"

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
    title=(fl.get("title") or "")
    print(f"  flow_id={FID} status={fl['status']} title={title!r}",flush=True)
    print(f"  görev (ilk 200): {PROMPT[:200]!r}",flush=True)

    # ——— D2/D3 HARD GATE: flow'un görevi hedefi mi hedefliyor (juiceshop DEĞİL)? Geçmezse HARD-STOP+çık.
    if "juiceshop" in title.lower():
        hard_stop(FID,"createFlow title 'juiceshop' içeriyor — yanlış görevle açıldı"); sys.exit(4)
    ok,msg=early_target_gate(FID,TARGET)
    print(f"  [gate] {msg}",flush=True)
    if ok is False:
        hard_stop(FID,"hedef kapısı: "+msg); sys.exit(4)
    # GERÇEK ajan harcaması: bu TAZE instance'ta tek flow var → TÜM msgchains = bu koşunun LLM harcaması.
    # (flow_id={FID} filtresi bu PentAGI sürümünde 0 dönebiliyordu → cap gerçek harcamayı GÖRMÜYORDU.)
    def spend():
        c=int(psql("SELECT count(*) FROM msgchains;") or 0)
        u=float(psql("SELECT COALESCE(SUM(usage_cost_in+usage_cost_out),0)::numeric(12,4) FROM msgchains;") or 0)
        return c,u
    t0=time.time(); reason=None; last_calls=-1; stable_t=time.time()
    while True:
        el=int(time.time()-t0)
        # SÜRE CAP EN BAŞTA — psql yavaş/asılı olsa BİLE 600s'de kesin keser (bu koşu 1402s'ye çıkmıştı:
        # spend() sorguları döngüyü geciktiriyordu; artık süre önce + psql timeout'lu).
        if el>=CAP_SEC: reason=f"SÜRE cap ({CAP_SEC}s)"; break
        calls,cost=spend()
        tcs=int(psql(f"SELECT count(*) FROM toolcalls WHERE flow_id={FID};") or 0)
        print(f"  [t={el}s] llm_calls={calls} tool_calls={tcs} cost=${cost:.4f}",flush=True)
        # SERT CAP — GERÇEK harcamaya bağlı; aşınca hard_stop (Anthropic-egress-kes + finishFlow + kill)
        if cost>=CAP_COST: reason=f"MALİYET cap (${CAP_COST})"; break
        if calls>=CAP_CALLS: reason=f"ÇAĞRI cap ({CAP_CALLS})"; break
        # BİTİŞ: flow terminal AMA yalnız harcama STABİL ise (yeni çağrı yok ~25s). 3a dersi: 'finished'
        # tek başına yetmez — backend async harcamaya devam edebilir; stabil olmadan bitirme.
        if calls!=last_calls: last_calls=calls; stable_t=time.time()
        stt=psql(f"SELECT status FROM flows WHERE id={FID};")
        if stt in ("finished","failed") and calls>0 and (time.time()-stable_t)>=25:
            reason=f"flow {stt} (harcama stabil)"; break
        time.sleep(5)
    hard_stop(FID,reason)
    # cap sonrası harcama DONMUŞ mu (sert-durdurma ispatı) — GERÇEK harcama (tüm msgchains)
    c1,_=spend(); time.sleep(20); c2,fc=spend()
    fcost=f"{fc:.4f}"
    fst=psql(f"SELECT status FROM flows WHERE id={FID};")
    frozen = "✓ DONDU" if c1==c2 else f"⚠ HÂLÂ ARTIYOR ({c1}->{c2})"
    print(f"== SON: calls={c2} cost=${fcost} flow.status={fst} | cap-sonrası-harcama: {frozen} (neden={reason}) ==",flush=True)
    print(f"== NOT: Anthropic egress kapalı; 3b'de yeni koşu için 'egress-harden-docker.sh' (--no-llm'siz) çalıştır ==",flush=True)

if __name__=="__main__": main()
