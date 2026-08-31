import os,re,time,hmac,base64,hashlib,secrets,sqlite3,asyncio,json,subprocess,urllib.parse
from contextlib import contextmanager
from pathlib import Path
from typing import Optional
import httpx
from fastapi import FastAPI,Request,HTTPException,Form
from fastapi.responses import HTMLResponse,RedirectResponse
from pydantic import BaseModel

DB=os.getenv("UNBOUND_ISP_DB","/var/lib/unbound-isp/dashboard.db")
SECRET=os.environ["UNBOUND_ISP_SESSION_SECRET"].encode()
CA_CERT=Path("/etc/unbound-isp/pki/ca.crt")
CA_KEY=Path("/etc/unbound-isp/pki/ca.key")
CLIENT_CERT=Path("/etc/unbound-isp/pki/controller.crt")
CLIENT_KEY=Path("/etc/unbound-isp/pki/controller.key")
app=FastAPI(title="Unbound ISP Dashboard",version="1.0",docs_url=None,redoc_url=None)

@contextmanager
def db():
    c=sqlite3.connect(DB,timeout=10);c.row_factory=sqlite3.Row
    try: yield c;c.commit()
    finally:c.close()

def init_db():
    with db() as c:c.executescript("""
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password_hash TEXT,salt TEXT,created_at INTEGER);
    CREATE TABLE IF NOT EXISTS nodes(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,host TEXT,port INTEGER,api_key TEXT,role TEXT,enabled INTEGER DEFAULT 1,allow_changes INTEGER DEFAULT 1,created_at INTEGER,UNIQUE(host,port));
    CREATE TABLE IF NOT EXISTS metrics(id INTEGER PRIMARY KEY AUTOINCREMENT,node_id INTEGER,ts INTEGER,q REAL,hit REAL,miss REAL,timeout REAL,reqmax REAL,lat REAL,cpu REAL,ram REAL,active INTEGER);
    CREATE INDEX IF NOT EXISTS idx_m ON metrics(node_id,ts);
    CREATE TABLE IF NOT EXISTS audits(id INTEGER PRIMARY KEY AUTOINCREMENT,ts INTEGER,user TEXT,node_id INTEGER,action TEXT,detail TEXT,result TEXT);
    CREATE TABLE IF NOT EXISTS pair_tokens(token TEXT PRIMARY KEY,expires INTEGER,used INTEGER DEFAULT 0);
    """)

def ph(p,s):return hashlib.pbkdf2_hmac("sha256",p.encode(),bytes.fromhex(s),220000).hex()
def create_user(u,p):
    s=secrets.token_hex(16)
    with db() as c:c.execute("INSERT OR REPLACE INTO users(username,password_hash,salt,created_at) VALUES(?,?,?,?)",(u,ph(p,s),s,int(time.time())))
def verify(u,p):
    with db() as c:r=c.execute("SELECT * FROM users WHERE username=?",(u,)).fetchone()
    return bool(r and hmac.compare_digest(r["password_hash"],ph(p,r["salt"])))
def sess(u):
    e=int(time.time())+43200; raw=f"{u}|{e}".encode(); sig=hmac.new(SECRET,raw,hashlib.sha256).hexdigest().encode()
    return base64.urlsafe_b64encode(raw+b"|"+sig).decode()
def user(req):
    try:
        raw=base64.urlsafe_b64decode(req.cookies.get("uis","")).decode();u,e,s=raw.rsplit("|",2)
        good=hmac.new(SECRET,f"{u}|{e}".encode(),hashlib.sha256).hexdigest()
        return u if hmac.compare_digest(s,good) and int(e)>time.time() else None
    except:return None
def need(req):
    u=user(req)
    if not u:raise HTTPException(401,"login necessário")
    return u

def f(v):
    try:return float(v)
    except:return None

async def ar(n,method,path,body=None):
    async with httpx.AsyncClient(verify=str(CA_CERT),cert=(str(CLIENT_CERT),str(CLIENT_KEY)),timeout=12) as c:
        r=await c.request(method,f"https://{n['host']}:{n['port']}{path}",headers={"X-API-Key":n["api_key"]},json=body)
    if r.status_code>=400:raise RuntimeError(r.text)
    return r.json()

async def collect(n):
    now=int(time.time())
    try:
        met,sys,hl=await asyncio.gather(ar(n,"GET","/api/v1/metrics"),ar(n,"GET","/api/v1/system"),ar(n,"GET","/api/v1/health"))
        s=met.get("stats",{})
        row=(n["id"],now,f(s.get("total.num.queries")),f(s.get("total.num.cachehits")),f(s.get("total.num.cachemiss")),
             f(s.get("total.num.queries_timed_out")),f(s.get("total.requestlist.max")),f(s.get("total.recursion.time.median")),
             sys.get("cpu_percent"),sys.get("ram_percent"),1 if hl.get("unbound_active") else 0)
    except: row=(n["id"],now,None,None,None,None,None,None,None,None,0)
    with db() as c:c.execute("INSERT INTO metrics(node_id,ts,q,hit,miss,timeout,reqmax,lat,cpu,ram,active) VALUES(?,?,?,?,?,?,?,?,?,?,?)",row)

async def loop():
    while True:
        try:
            with db() as c:ns=[dict(r) for r in c.execute("SELECT * FROM nodes WHERE enabled=1")]
            for n in ns:await collect(n)
            with db() as c:c.execute("DELETE FROM metrics WHERE ts<?",(int(time.time())-7*86400,))
        except:pass
        await asyncio.sleep(10)

@app.on_event("startup")
async def start():init_db();asyncio.create_task(loop())

class Opt(BaseModel):option:str;value:str
class Act(BaseModel):action:str
class Raw(BaseModel):content:str
class ACL(BaseModel):cidr:str;action:str="allow"
class Join(BaseModel):
    token:str;name:str;host:str;port:int=9443;api_key:str;csr_b64:str

@app.get("/login",response_class=HTMLResponse)
def lp():return HTMLResponse(LOGIN)
@app.post("/login")
def li(username:str=Form(...),password:str=Form(...)):
    if not verify(username,password):return HTMLResponse(LOGIN.replace("<!--ERR-->","<p class='err'>Login inválido</p>"),401)
    r=RedirectResponse("/",302);r.set_cookie("uis",sess(username),httponly=True,samesite="strict",secure=True,max_age=43200);return r
@app.post("/logout")
def lo():
    r=RedirectResponse("/login",302);r.delete_cookie("uis");return r
@app.get("/",response_class=HTMLResponse)
def home(req:Request):
    if not user(req):return RedirectResponse("/login",302)
    return HTMLResponse(INDEX)

@app.get("/api/nodes")
def nodes(req:Request):
    need(req)
    with db() as c:return [dict(r) for r in c.execute("SELECT id,name,host,port,role,enabled,allow_changes,created_at FROM nodes ORDER BY id")]

@app.get("/api/nodes/{nid}/snapshot")
async def snap(nid:int,req:Request):
    need(req)
    with db() as c:r=c.execute("SELECT * FROM nodes WHERE id=?",(nid,)).fetchone()
    if not r:raise HTTPException(404,"DNS não encontrado")
    n=dict(r)
    try:
        h,s,m=await asyncio.gather(ar(n,"GET","/api/v1/health"),ar(n,"GET","/api/v1/system"),ar(n,"GET","/api/v1/metrics"))
        return {"ok":True,"node":{k:n[k] for k in ("id","name","host","port","role","allow_changes")},"health":h,"system":s,"metrics":m}
    except Exception as e:return {"ok":False,"error":str(e),"node":{k:n[k] for k in ("id","name","host","port","role","allow_changes")}}

@app.get("/api/nodes/{nid}/history")
def hist(nid:int,req:Request,hours:int=1):
    need(req);since=int(time.time())-max(1,min(hours,168))*3600
    with db() as c:return [dict(r) for r in c.execute("SELECT * FROM metrics WHERE node_id=? AND ts>=? ORDER BY ts",(nid,since))]

async def proxy_write(nid,req,path,body,action):
    u=need(req)
    with db() as c:r=c.execute("SELECT * FROM nodes WHERE id=?",(nid,)).fetchone()
    if not r:raise HTTPException(404,"DNS não encontrado")
    n=dict(r)
    if not n["allow_changes"]:raise HTTPException(403,"alterações desabilitadas")
    try:o=await ar(n,"POST",path,body);res="OK"
    except Exception as e:o={"error":str(e)};res="ERRO"
    with db() as c:c.execute("INSERT INTO audits(ts,user,node_id,action,detail,result) VALUES(?,?,?,?,?,?)",(int(time.time()),u,nid,action,json.dumps(body),res))
    if res!="OK":raise HTTPException(500,o)
    return o

@app.post("/api/nodes/{nid}/option")
async def op(nid:int,d:Opt,req:Request):return await proxy_write(nid,req,"/api/v1/unbound/option",d.model_dump(),"OPTION")
@app.post("/api/nodes/{nid}/action")
async def ac(nid:int,d:Act,req:Request):return await proxy_write(nid,req,"/api/v1/unbound/action",d.model_dump(),"ACTION")
@app.post("/api/nodes/{nid}/acl/add")
async def aa(nid:int,d:ACL,req:Request):return await proxy_write(nid,req,"/api/v1/unbound/acl/add",d.model_dump(),"ACL_ADD")
@app.post("/api/nodes/{nid}/acl/remove")
async def ad(nid:int,d:ACL,req:Request):return await proxy_write(nid,req,"/api/v1/unbound/acl/remove",d.model_dump(),"ACL_REMOVE")
@app.post("/api/nodes/{nid}/config")
async def rc(nid:int,d:Raw,req:Request):return await proxy_write(nid,req,"/api/v1/unbound/config",d.model_dump(),"RAW_CONFIG")

@app.get("/api/nodes/{nid}/troubleshooting")
async def trouble(nid:int,req:Request,deep:int=0,domain:str=""):
    need(req)
    with db() as c:r=c.execute("SELECT * FROM nodes WHERE id=?",(nid,)).fetchone()
    if not r:raise HTTPException(404,"DNS não encontrado")
    q=f"/api/v1/troubleshooting?deep={1 if deep else 0}"
    if domain.strip(): q += "&domain=" + urllib.parse.quote(domain.strip())
    return await ar(dict(r),"GET",q)

@app.get("/api/nodes/{nid}/config")
async def gc(nid:int,req:Request):
    need(req)
    with db() as c:r=c.execute("SELECT * FROM nodes WHERE id=?",(nid,)).fetchone()
    if not r:raise HTTPException(404,"DNS não encontrado")
    return await ar(dict(r),"GET","/api/v1/config")
@app.get("/api/nodes/{nid}/logs")
async def gl(nid:int,req:Request):
    need(req)
    with db() as c:r=c.execute("SELECT * FROM nodes WHERE id=?",(nid,)).fetchone()
    if not r:raise HTTPException(404,"DNS não encontrado")
    return await ar(dict(r),"GET","/api/v1/logs")
@app.get("/api/audits")
def aud(req:Request):
    need(req)
    with db() as c:return [dict(r) for r in c.execute("SELECT a.*,n.name node FROM audits a LEFT JOIN nodes n ON n.id=a.node_id ORDER BY a.id DESC LIMIT 200")]

@app.post("/api/pair/join")
def join(d:Join):
    now=int(time.time())
    with db() as c:r=c.execute("SELECT * FROM pair_tokens WHERE token=? AND used=0 AND expires>?",(d.token,now)).fetchone()
    if not r:raise HTTPException(403,"token de pareamento inválido/expirado")
    if not re.fullmatch(r"[0-9A-Fa-f:.]+",d.host):raise HTTPException(400,"IP inválido")
    csr=base64.b64decode(d.csr_b64)
    td=Path("/tmp/unbound-isp-pair");td.mkdir(exist_ok=True)
    csrfile=td/f"{secrets.token_hex(4)}.csr";crtfile=Path(str(csrfile)+".crt");csrfile.write_bytes(csr)
    p=subprocess.run(["openssl","x509","-req","-in",str(csrfile),"-CA",str(CA_CERT),"-CAkey",str(CA_KEY),"-CAcreateserial",
                      "-out",str(crtfile),"-days","825","-sha256","-copy_extensions","copy"],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    if p.returncode:raise HTTPException(500,p.stdout)
    cert=base64.b64encode(crtfile.read_bytes()).decode();ca=base64.b64encode(CA_CERT.read_bytes()).decode()
    with db() as c:
        c.execute("UPDATE pair_tokens SET used=1 WHERE token=?",(d.token,))
        c.execute("INSERT OR REPLACE INTO nodes(name,host,port,api_key,role,enabled,allow_changes,created_at) VALUES(?,?,?,?,?,1,1,?)",
                  (d.name,d.host,d.port,d.api_key,"DNS2",now))
    return {"ok":True,"cert_b64":cert,"ca_b64":ca}

LOGIN="""<!doctype html><meta name=viewport content="width=device-width"><style>body{background:#080d19;color:#eef3ff;font-family:system-ui;display:grid;place-items:center;height:100vh}.b{background:#111a2b;padding:28px;border-radius:16px;width:min(380px,85vw)}input,button{width:100%;box-sizing:border-box;padding:12px;margin:7px 0;border-radius:9px;border:1px solid #31405e;background:#0b1220;color:white}button{background:#eef3ff;color:#08101d;font-weight:800}.err{color:#ff808c}</style><div class=b><h2>UNBOUND ISP</h2><!--ERR--><form method=post><input name=username placeholder=Usuário><input type=password name=password placeholder=Senha><button>Entrar</button></form></div>"""

INDEX=r"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Unbound ISP</title>
<style>:root{--b:#080d19;--p:#101827;--l:#27334d;--t:#edf3ff;--m:#91a0bb;--g:#4bd39a;--r:#ff6b7a}*{box-sizing:border-box}body{margin:0;background:var(--b);color:var(--t);font-family:system-ui}header{height:64px;border-bottom:1px solid var(--l);display:flex;align-items:center;justify-content:space-between;padding:0 22px}.w{max-width:1450px;margin:auto;padding:22px}.cards,.nodes{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:13px}.card,.panel{background:var(--p);border:1px solid var(--l);border-radius:14px;padding:16px}.node{cursor:pointer}.muted{color:var(--m)}.v{font-size:27px;font-weight:850}.dot{width:9px;height:9px;border-radius:50%;display:inline-block;background:var(--r)}.ok{background:var(--g)}button,input,textarea,select{background:#172035;color:white;border:1px solid var(--l);border-radius:8px;padding:10px}button{cursor:pointer;font-weight:700}textarea{width:100%;min-height:420px;font-family:monospace}.row{display:flex;gap:9px;flex-wrap:wrap;align-items:center}.grid{display:grid;grid-template-columns:1fr 1fr;gap:13px}pre{white-space:pre-wrap;background:#080d19;padding:12px;border-radius:8px;max-height:420px;overflow:auto}@media(max-width:750px){.grid{grid-template-columns:1fr}.w{padding:13px}}</style></head>
<body><header><b>UNBOUND ISP <span class=muted>DNS Central</span></b><form method=post action=/logout><button>Sair</button></form></header><main class=w id=main></main>
<script>
const A=async(u,o={})=>{let r=await fetch(u,{headers:{'Content-Type':'application/json'},...o}),d=await r.json().catch(()=>({}));if(!r.ok)throw Error(JSON.stringify(d.detail||d));return d},F=x=>x==null?'—':Number(x).toLocaleString('pt-BR',{maximumFractionDigits:2});
async function home(){let ns=await A('/api/nodes');main.innerHTML='<h1>Visão geral</h1><div class=nodes id=ns></div><p><button onclick="audit()">Auditoria</button></p>';for(let n of ns){let s=await A('/api/nodes/'+n.id+'/snapshot'),st=(s.metrics||{}).stats||{},h=+(st['total.num.cachehits']||0),m=+(st['total.num.cachemiss']||0),p=h+m?100*h/(h+m):0,sy=s.system||{};ns=document.getElementById('ns');let d=document.createElement('div');d.className='card node';d.onclick=()=>detail(n.id);d.innerHTML=`<div><span class="dot ${s.ok&&s.health?.unbound_active?'ok':''}"></span> <b>${n.name}</b></div><p class=muted>${n.role} · ${n.host}</p><div class=cards><div><span class=muted>Cache hit</span><div class=v>${F(p)}%</div></div><div><span class=muted>CPU</span><div class=v>${F(sy.cpu_percent)}%</div></div></div>`;ns.appendChild(d)}}
async function detail(id){let s=await A('/api/nodes/'+id+'/snapshot'),st=(s.metrics||{}).stats||{},h=+(st['total.num.cachehits']||0),m=+(st['total.num.cachemiss']||0),p=h+m?100*h/(h+m):0,sy=s.system||{};main.innerHTML=`<button onclick=home()>← Voltar</button><h1>${s.node.name}</h1><p class=muted>${s.node.role} · ${s.node.host}:${s.node.port}</p><div class=cards><div class=card><span class=muted>Cache hit</span><div class=v>${F(p)}%</div></div><div class=card><span class=muted>CPU</span><div class=v>${F(sy.cpu_percent)}%</div></div><div class=card><span class=muted>RAM</span><div class=v>${F(sy.ram_percent)}%</div></div><div class=card><span class=muted>Latência</span><div class=v>${F(st['total.recursion.time.median'])}</div></div></div><div class=grid style="margin-top:13px"><div class=panel><h3>Ações</h3><div class=row><button onclick="act(${id},'reload_keep_cache')">Reload</button><button onclick="act(${id},'restart')">Restart</button><button onclick="act(${id},'flush_all')">Flush cache</button><button onclick="logs(${id})">Logs</button><button onclick="trouble(${id},0)">Troubleshooting</button><button onclick="trouble(${id},1)">Troubleshooting profundo</button></div></div><div class=panel><h3>Parâmetro seguro</h3><div class=row><input id=o placeholder=prefetch><input id=v placeholder=yes><button onclick="opt(${id})">Aplicar</button></div></div><div class=panel><h3>ACL</h3><div class=row><input id=cidr placeholder="100.64.0.0/10"><select id=aa><option>allow</option><option>deny</option><option>refuse</option></select><button onclick="acl(${id},'add')">Adicionar</button><button onclick="acl(${id},'remove')">Remover</button></div></div><div class=panel><h3>Teste de domínio específico</h3><p class=muted>Use quando um cliente reclamar de um site específico.</p><div class=row><input id=tdomain placeholder="instagram.com"><button onclick="domainTest(${id},0)">Testar</button><button onclick="domainTest(${id},1)">Teste profundo</button></div></div><div class=panel><h3>Configuração avançada</h3><button onclick="cfg(${id})">Abrir editor</button></div></div>`}
async function act(i,a){if(confirm('Executar '+a+'?')){await A('/api/nodes/'+i+'/action',{method:'POST',body:JSON.stringify({action:a})});alert('OK');detail(i)}}
async function opt(i){if(confirm('Aplicar alteração com backup e rollback automático?')){await A('/api/nodes/'+i+'/option',{method:'POST',body:JSON.stringify({option:o.value,value:v.value})});alert('OK');detail(i)}}
async function acl(i,x){await A('/api/nodes/'+i+'/acl/'+x,{method:'POST',body:JSON.stringify({cidr:cidr.value,action:aa.value})});alert('OK');detail(i)}
async function domainTest(i,d){let domain=(document.getElementById('tdomain')?.value||'').trim().toLowerCase().replace(/^https?:\/\//,'').split('/')[0];if(!domain){alert('Digite um domínio, por exemplo: instagram.com');return}main.innerHTML='<button onclick="detail('+i+')">← Voltar</button><h2>Testando '+domain+'...</h2><p class=muted>Diagnóstico direcionado · '+(d?'profundo':'normal')+'</p>';try{let x=await A('/api/nodes/'+i+'/troubleshooting?deep='+d+'&domain='+encodeURIComponent(domain));main.innerHTML='<button onclick="detail('+i+')">← Voltar</button><h2>Teste direcionado: '+domain+'</h2><p class=muted>Executado pelo próprio DNS selecionado · '+(d?'modo profundo':'modo normal')+'</p><pre></pre>';document.querySelector('pre').textContent=x.output}catch(e){main.innerHTML+='<pre>'+e+'</pre>'}}
async function trouble(i,d){main.innerHTML='<button onclick="detail('+i+')">← Voltar</button><h2>Executando troubleshooting...</h2><p class=muted>Modo '+(d?'profundo':'normal')+'</p>';try{let x=await A('/api/nodes/'+i+'/troubleshooting?deep='+d);main.innerHTML='<button onclick="detail('+i+')">← Voltar</button><h2>Troubleshooting '+(d?'profundo':'normal')+'</h2><pre></pre>';document.querySelector('pre').textContent=x.output}catch(e){main.innerHTML+='<pre>'+e+'</pre>'}}
async function logs(i){let x=await A('/api/nodes/'+i+'/logs');main.innerHTML='<button onclick="detail('+i+')">← Voltar</button><h2>Logs</h2><pre></pre>';document.querySelector('pre').textContent=x.logs}
async function cfg(i){let x=await A('/api/nodes/'+i+'/config');main.innerHTML='<button onclick="detail('+i+')">← Voltar</button><h2>Configuração avançada</h2><p class=muted>Ao salvar: backup → checkconf → restart → teste DNS/DNSSEC → rollback em falha.</p><textarea id=c></textarea><p><button onclick="savecfg('+i+')">Validar e aplicar</button></p>';c.value=x.content}
async function savecfg(i){if(confirm('Aplicar configuração completa?')){await A('/api/nodes/'+i+'/config',{method:'POST',body:JSON.stringify({content:c.value})});alert('Configuração aplicada');detail(i)}}
async function audit(){let x=await A('/api/audits');main.innerHTML='<button onclick=home()>← Voltar</button><h2>Auditoria</h2><pre></pre>';document.querySelector('pre').textContent=JSON.stringify(x,null,2)}
home();setInterval(()=>{if(document.querySelector('h1')?.textContent==='Visão geral')home()},15000)
</script></body></html>"""
