import subprocess, re
FID=open("/opt/pentagi-run/flow_id").read().strip()
NL="\x01"
def q(sql):
    return subprocess.run(["docker","exec","pgvector","psql","-U","postgres","-d","pentagidb","-tAqc",sql],
                          capture_output=True,text=True).stdout
def strip_ansi(s): return re.sub(r"\x1b\[[0-9;]*m","",s)
# her termlog TEK satır: iç newline -> \x01
raw=q(f"SELECT id||'\t'||type||'\t'||replace(replace(coalesce(text,''),E'\\r',''),E'\\n','{NL}') "
      f"FROM termlogs WHERE flow_id={FID} ORDER BY id;")
logs=[]
for line in raw.strip("\n").split("\n"):
    if not line.strip(): continue
    tid,typ,text=line.split("\t",2)
    logs.append({"id":tid,"type":typ,"text":strip_ansi(text.replace(NL,"\n"))})
# komut(stdin) -> yanıt(stdout) eşle
pairs=[]; cur=None
for l in logs:
    if l["type"]=="stdin":
        m=re.search(r"q=([^\"'\s]*)", l["text"]); cur={"payload":m.group(1) if m else "?","cmd":l["text"].strip()}
    elif l["type"]=="stdout" and cur is not None:
        t=l["text"]
        cur["http"]=(re.search(r"HTTP/1\.1 (\d{3})",t) or [None,"?"])[1]
        cur["clen"]=int((re.search(r"Content-Length[^\d]*(\d+)",t,re.I) or [0,0])[1])
        cur["items"]=len(re.findall(r'"id":\d+',t))
        cur["err"]=bool(re.search(r'SQLITE_ERROR|SQL syntax|unrecognized token|near "',t,re.I))
        cur["termlog"]=l["id"]; pairs.append(cur); cur=None
def find(frag):
    for p in pairs:
        if frag in p["payload"]: return p
    return None
base=find("apple"); qq=find("%27") if find("%27") and "))" not in find("%27")["payload"] else None
qbreak=next((p for p in pairs if "%27))" in p["payload"]),None)
# %27 tek başına (kırık değil)
qsingle=next((p for p in pairs if p["payload"] in ("%27","'") ),None)

base_items=base["items"] if base else 0
error_based=any(p["err"] for p in pairs)
narr=int((q(f"SELECT count(*) FROM toolcalls WHERE flow_id={FID} AND (coalesce(result,'')||coalesce(args::text,'')) ~* 'SQLITE_ERROR';").strip() or 0))
boolean_based=bool(qbreak and base_items and qbreak["items"]>=max(2*base_items,base_items+5))

print("="*76)
print(f"  PENTAGI KANIT-BAĞLAYICI — GERÇEK DB SATIRLARI (flow_id={FID}, uydurma YOK)")
print("="*76)
print(f"  ham artefakt (komut→yanıt çiftleri): {len(pairs)}")
for p in pairs:
    print(f"    • q={p['payload']:<8} -> HTTP {p['http']}  items={p['items']}  len={p['clen']}B  [termlog#{p['termlog']}]")
print(f"  ham artefaktta SQL-hata imzası: {'VAR' if error_based else 'YOK (0)'}   |   ajan anlatısında 'SQLITE_ERROR': {narr} toolcall (iddia, kanıt değil)")
print("-"*76); print("  3-KATMAN (ajanın SÖZÜNE değil, HAM ARTEFAKTA bağlı):"); print("-"*76)
n_k=n_h=n_b=0
if boolean_based:
    n_k=1; print(f"[KANITLI] SQL Enjeksiyonu (boolean/comment-based) — /rest/products/search?q=")
    print(f"      -> HAM KANIT termlog#{qbreak['termlog']}: q=')) -- => {qbreak['items']} ürün vs baseline {base_items} "
          f"({qbreak['items']//max(base_items,1)}x şişme, {qbreak['clen']}B vs {base['clen']}B). Deterministik & tekrarlanabilir.\n")
if narr>0 and not error_based:
    n_h=1; print(f"[HAYALET] SQL Enjeksiyonu (error-based / 'SQLITE_ERROR') — ajan anlatısında geçiyor")
    print(f"      -> ajan {narr} toolcall'da 'SQLITE_ERROR' yazdı; HAM artefaktlarda SQL-hata imzası SIFIR "
          f"=> error-based yorum ELENİR (hata hiç oluşmadı). 'Ajanın iddiasına güvenme'nin canlı örneği.\n")
if qsingle and not qsingle["err"] and qsingle["items"]==0:
    n_b=1; print(f"[BELİRSİZ] Tek-tırnak probe q=' — boş sonuç kümesi")
    print(f"      -> HAM KANIT termlog#{qsingle['termlog']}: HTTP {qsingle['http']}, {qsingle['items']} ürün (boş). "
          f"Ne hata ne şişme => tek başına sonuçsuz; SİLİNMEZ, insan-inceleme.\n")
print("-"*76)
print(f"  ÖZET: KANITLI={n_k}  HAYALET={n_h}  BELİRSİZ={n_b}  — üçü de tek gerçek bulgudan, GERÇEK satırlardan doğdu.")
print("="*76)
