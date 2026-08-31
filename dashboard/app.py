import os,re,time,hmac,base64,hashlib,secrets,sqlite3,asyncio,json,subprocess,urllib.parse,ssl
from contextlib import contextmanager
from pathlib import Path
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
PANEL_VERSION="2.0"
app=FastAPI(title="Unbound ISP Dashboard",version=PANEL_VERSION,docs_url=None,redoc_url=None)

@contextmanager
def db():
    c=sqlite3.connect(DB,timeout=10);c.row_factory=sqlite3.Row
    try: yield c;c.commit()
    finally:c.close()

def init_db():
    with db() as c:
        c.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password_hash TEXT,salt TEXT,created_at INTEGER);
        CREATE TABLE IF NOT EXISTS nodes(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,host TEXT,port INTEGER,api_key TEXT,role TEXT,enabled INTEGER DEFAULT 1,allow_changes INTEGER DEFAULT 1,created_at INTEGER,UNIQUE(host,port));
        CREATE TABLE IF NOT EXISTS metrics(id INTEGER PRIMARY KEY AUTOINCREMENT,node_id INTEGER,ts INTEGER,q REAL,hit REAL,miss REAL,timeout REAL,reqmax REAL,lat REAL,cpu REAL,ram REAL,active INTEGER);
        CREATE INDEX IF NOT EXISTS idx_m ON metrics(node_id,ts);
        CREATE TABLE IF NOT EXISTS audits(id INTEGER PRIMARY KEY AUTOINCREMENT,ts INTEGER,user TEXT,node_id INTEGER,action TEXT,detail TEXT,result TEXT);
        CREATE TABLE IF NOT EXISTS pair_tokens(token TEXT PRIMARY KEY,expires INTEGER,used INTEGER DEFAULT 0);
        """)
        cols={r[1] for r in c.execute("PRAGMA table_info(metrics)")}
        extra={"ipv4":"REAL","ipv6":"REAL","noerror":"REAL","nxdomain":"REAL","refused":"REAL","servfail":"REAL","nodata":"REAL","secure":"REAL","load1":"REAL","uptime":"REAL"}
        for k,t in extra.items():
            if k not in cols:c.execute(f"ALTER TABLE metrics ADD COLUMN {k} {t}")

def ph(p,s):return hashlib.pbkdf2_hmac("sha256",p.encode(),bytes.fromhex(s),220000).hex()
def create_user(u,p):
    s=secrets.token_hex(16)
    with db() as c:c.execute("INSERT OR REPLACE INTO users(username,password_hash,salt,created_at) VALUES(?,?,?,?)",(u,ph(p,s),s,int(time.time())))
def verify(u,p):
    with db() as c:r=c.execute("SELECT * FROM users WHERE username=?",(u,)).fetchone()
    return bool(r and hmac.compare_digest(r["password_hash"],ph(p,r["salt"])))
def sess(u):
    e=int(time.time())+43200;raw=f"{u}|{e}".encode();sig=hmac.new(SECRET,raw,hashlib.sha256).hexdigest().encode();return base64.urlsafe_b64encode(raw+b"|"+sig).decode()
def user(req):
    try:
        raw=base64.urlsafe_b64decode(req.cookies.get("uis","")).decode();u,e,s=raw.rsplit("|",2);good=hmac.new(SECRET,f"{u}|{e}".encode(),hashlib.sha256).hexdigest();return u if hmac.compare_digest(s,good) and int(e)>time.time() else None
    except:return None
def need(req):
    u=user(req)
    if not u:raise HTTPException(401,"login necessário")
    return u
def f(v):
    try:return float(v)
    except:return None

async def ar(n,method,path,body=None):
    ctx=ssl.create_default_context(cafile=str(CA_CERT));ctx.load_cert_chain(certfile=str(CLIENT_CERT),keyfile=str(CLIENT_KEY))
    async with httpx.AsyncClient(verify=ctx,timeout=12,trust_env=False) as c:
        r=await c.request(method,f"https://{n['host']}:{n['port']}{path}",headers={"X-API-Key":n["api_key"]},json=body)
    if r.status_code>=400:raise RuntimeError(r.text)
    return r.json()

def sv(s,k):return f(s.get(k)) or 0.0

async def collect(n):
    now=int(time.time())
    try:
        met,sy,hl=await asyncio.gather(ar(n,"GET","/api/v1/metrics"),ar(n,"GET","/api/v1/system"),ar(n,"GET","/api/v1/health"))
        s=met.get("stats",{});q=sv(s,"total.num.queries");ipv6=sv(s,"num.query.ipv6");ipv4=max(0,q-ipv6)
        row=(n["id"],now,q,sv(s,"total.num.cachehits"),sv(s,"total.num.cachemiss"),f(s.get("total.num.queries_timed_out")),sv(s,"total.requestlist.max"),sv(s,"total.recursion.time.median"),sy.get("cpu_percent"),sy.get("ram_percent"),1 if hl.get("unbound_active") else 0,ipv4,ipv6,sv(s,"num.answer.rcode.NOERROR"),sv(s,"num.answer.rcode.NXDOMAIN"),sv(s,"num.answer.rcode.REFUSED"),sv(s,"num.answer.rcode.SERVFAIL"),sv(s,"num.answer.rcode.nodata"),sv(s,"num.answer.secure"),(sy.get("loadavg") or [None])[0],sv(s,"time.up"))
    except Exception:
        row=(n["id"],now,None,None,None,None,None,None,None,None,0,None,None,None,None,None,None,None,None,None,None)
    with db() as c:c.execute("INSERT INTO metrics(node_id,ts,q,hit,miss,timeout,reqmax,lat,cpu,ram,active,ipv4,ipv6,noerror,nxdomain,refused,servfail,nodata,secure,load1,uptime) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",row)

async def loop():
    while True:
        try:
            with db() as c:ns=[dict(r) for r in c.execute("SELECT * FROM nodes WHERE enabled=1")]
            for n in ns:await collect(n)
            with db() as c:c.execute("DELETE FROM metrics WHERE ts<?",(int(time.time())-7*86400,))
        except Exception:pass
        await asyncio.sleep(10)

@app.on_event("startup")
async def start():init_db();asyncio.create_task(loop())

class Opt(BaseModel):option:str;value:str
class Act(BaseModel):action:str
class Raw(BaseModel):content:str
class ACL(BaseModel):cidr:str;action:str="allow"
class Join(BaseModel):token:str;name:str;host:str;port:int=9443;api_key:str;csr_b64:str

@app.get("/login",response_class=HTMLResponse)
def lp():return HTMLResponse(LOGIN)
@app.post("/login")
def li(username:str=Form(...),password:str=Form(...)):
    if not verify(username,password):return HTMLResponse(LOGIN.replace("<!--ERR-->","<p class='err'>Login inválido</p>"),401)
    r=RedirectResponse("/",302);r.set_cookie("uis",sess(username),httponly=True,samesite="strict",secure=True,max_age=43200);return r
@app.post("/logout")
def lo():r=RedirectResponse("/login",302);r.delete_cookie("uis");return r
@app.get("/",response_class=HTMLResponse)
def home(req:Request):return RedirectResponse("/login",302) if not user(req) else HTMLResponse(INDEX)

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
        h,s,m=await asyncio.gather(ar(n,"GET","/api/v1/health"),ar(n,"GET","/api/v1/system"),ar(n,"GET","/api/v1/metrics"));return {"ok":True,"panel_version":PANEL_VERSION,"node":{k:n[k] for k in ("id","name","host","port","role","allow_changes")},"health":h,"system":s,"metrics":m}
    except Exception as e:return {"ok":False,"error":str(e),"panel_version":PANEL_VERSION,"node":{k:n[k] for k in ("id","name","host","port","role","allow_changes")}}
@app.get("/api/nodes/{nid}/history")
def hist(nid:int,req:Request,minutes:int=30):
    need(req);mins=max(5,min(minutes,10080));since=int(time.time())-mins*60
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
    q=f"/api/v1/troubleshooting?deep={1 if deep else 0}"+("&domain="+urllib.parse.quote(domain.strip()) if domain.strip() else "")
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
    csr=base64.b64decode(d.csr_b64);td=Path("/tmp/unbound-isp-pair");td.mkdir(exist_ok=True);csrfile=td/f"{secrets.token_hex(4)}.csr";crtfile=Path(str(csrfile)+".crt");csrfile.write_bytes(csr)
    p=subprocess.run(["openssl","x509","-req","-in",str(csrfile),"-CA",str(CA_CERT),"-CAkey",str(CA_KEY),"-CAcreateserial","-out",str(crtfile),"-days","825","-sha256","-copy_extensions","copy"],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    if p.returncode:raise HTTPException(500,p.stdout)
    cert=base64.b64encode(crtfile.read_bytes()).decode();ca=base64.b64encode(CA_CERT.read_bytes()).decode()
    with db() as c:
        c.execute("UPDATE pair_tokens SET used=1 WHERE token=?",(d.token,));c.execute("INSERT OR REPLACE INTO nodes(name,host,port,api_key,role,enabled,allow_changes,created_at) VALUES(?,?,?,?,?,1,1,?)",(d.name,d.host,d.port,d.api_key,"DNS2",now))
    return {"ok":True,"cert_b64":cert,"ca_b64":ca}

LOGIN="""<!doctype html><meta name=viewport content='width=device-width'><style>body{background:#07111f;color:#eef5ff;font-family:system-ui;display:grid;place-items:center;height:100vh}.b{background:#0d1a2b;padding:30px;border:1px solid #23344f;border-radius:18px;width:min(390px,86vw);box-shadow:0 20px 80px #0008}input,button{width:100%;box-sizing:border-box;padding:12px;margin:7px 0;border-radius:9px;border:1px solid #30425f;background:#091523;color:white}button{background:#1684ff;color:white;font-weight:800}.err{color:#ff6d78}</style><div class=b><h2>UNBOUND ISP</h2><p style='color:#8fa7c4'>DNS Central</p><!--ERR--><form method=post><input name=username placeholder=Usuário><input type=password name=password placeholder=Senha><button>Entrar</button></form></div>"""

INDEX=r"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Unbound ISP DNS Central</title><style>
:root{--bg:#07111f;--side:#081522;--panel:#0d1a2b;--line:#24364e;--txt:#edf5ff;--mut:#8fa7c4;--blue:#2196f3;--green:#4bd65d;--red:#ff4655;--yellow:#ffb000;--purple:#b54cff;--cyan:#19d3c5}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font-family:Inter,system-ui,Arial}.app{display:grid;grid-template-columns:195px 1fr;min-height:100vh}.side{background:linear-gradient(180deg,#07111f,#081522);border-right:1px solid var(--line);padding:20px 12px;position:sticky;top:0;height:100vh}.brand{font-weight:900;font-size:18px;margin:5px 8px 4px}.sub{color:var(--mut);font-size:12px;margin:0 8px 24px}.nav button{width:100%;text-align:left;margin:4px 0;background:transparent;border:0;color:#dbe8f7;padding:12px;border-radius:9px;cursor:pointer}.nav button:hover,.nav .on{background:#11243a;color:#55adff}.statusbox{position:absolute;left:12px;right:12px;bottom:20px;border:1px solid var(--line);border-radius:10px;padding:12px;font-size:12px;background:#091625}.main{padding:18px 22px 54px;overflow:hidden}.top{display:flex;justify-content:space-between;gap:10px;align-items:center;border-bottom:1px solid var(--line);padding-bottom:14px}.topctrl{display:flex;gap:9px;flex-wrap:wrap}.ctl,button,input,select,textarea{background:#0b1929;border:1px solid var(--line);color:white;border-radius:8px;padding:9px 11px}.kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-top:14px}.card,.panel{background:linear-gradient(180deg,#0d1a2b,#0a1726);border:1px solid var(--line);border-radius:12px;padding:13px}.k .n{font-size:24px;font-weight:900;margin:4px 0}.k .p{font-size:12px}.g{display:grid;gap:10px;margin-top:10px}.g2{grid-template-columns:1fr 1fr}.g4{grid-template-columns:repeat(4,1fr)}.g3{grid-template-columns:1fr 1.2fr 1fr}.title{font-weight:850;font-size:14px}.mut{color:var(--mut)}.big{font-size:25px;font-weight:900}.green{color:var(--green)}.red{color:var(--red)}.yellow{color:var(--yellow)}.blue{color:var(--blue)}.purple{color:var(--purple)}.cyan{color:var(--cyan)}canvas{width:100%;height:155px;display:block;margin-top:8px}.mini{height:38px}.metric{display:flex;justify-content:space-between;margin:6px 0;font-size:13px}.donut{width:130px;height:130px;border-radius:50%;margin:10px auto;position:relative}.donut:after{content:'';position:absolute;inset:27px;background:#0b1827;border-radius:50%}.actions{display:flex;gap:8px;flex-wrap:wrap}.actions button{cursor:pointer;font-weight:700}.tools{display:grid;grid-template-columns:1.3fr 1fr 1fr;gap:10px;margin-top:10px}.row{display:flex;gap:7px;flex-wrap:wrap}.row input{flex:1;min-width:150px}pre{white-space:pre-wrap;background:#06101c;padding:13px;border-radius:8px;max-height:520px;overflow:auto}.footer{position:fixed;left:195px;right:0;bottom:0;background:#07111ff2;border-top:1px solid var(--line);height:32px;display:flex;align-items:center;gap:25px;padding:0 18px;font-size:11px;color:#aec0d5}.pill{font-size:11px;padding:3px 7px;border-radius:12px;background:#0d2d1c;color:#6bea84}.editor textarea{width:100%;min-height:500px;font-family:monospace}@media(max-width:1150px){.kpis{grid-template-columns:repeat(3,1fr)}.g4{grid-template-columns:1fr 1fr}.g3{grid-template-columns:1fr}.tools{grid-template-columns:1fr}}@media(max-width:760px){.app{grid-template-columns:1fr}.side{display:none}.main{padding:12px}.kpis{grid-template-columns:1fr 1fr}.g2,.g4{grid-template-columns:1fr}.footer{left:0;overflow:auto}.top{align-items:flex-start;flex-direction:column}}
</style></head><body><div class=app><aside class=side><div class=brand>🛡️ UNBOUND ISP</div><div class=sub>DNS Central</div><div class=nav><button class=on onclick='dashboard()'>▣ Visão geral</button><button onclick='servers()'>▤ Servidores</button><button onclick='audit()'>⌁ Auditoria</button><button onclick='showManage()'>⚙ Configurações</button></div><div class=statusbox><b>Status do sistema</b><p><span class=green>● Online</span></p><div>Coleta <b>10 segundos</b></div><div>Painel <b>v2.0</b></div></div></aside><main class=main><div id=main></div></main><div class=footer id=foot></div></div><script>
const A=async(u,o={})=>{let r=await fetch(u,{headers:{'Content-Type':'application/json'},...o}),d=await r.json().catch(()=>({}));if(!r.ok)throw Error(JSON.stringify(d.detail||d));return d};const F=(x,d=2)=>x==null||!isFinite(+x)?'—':Number(x).toLocaleString('pt-BR',{maximumFractionDigits:d});let NODE=null,MIN=30,REF=null;
function rate(a,b,k){let dt=(b.ts-a.ts)||1,x=(+b[k]||0)-(+a[k]||0);return Math.max(0,x/dt)}function pct(v,t){return t?100*v/t:0}function uptime(s){s=Math.max(0,+s||0);let d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return (d?d+'d ':'')+h+'h '+m+'m'}
function chart(id,rows,key,color,delta=false){let c=document.getElementById(id);if(!c)return;let ctx=c.getContext('2d'),w=c.width=c.clientWidth*devicePixelRatio,h=c.height=155*devicePixelRatio;ctx.scale(devicePixelRatio,devicePixelRatio);w=c.clientWidth;h=155;let vals=[];if(delta){for(let i=1;i<rows.length;i++)vals.push(rate(rows[i-1],rows[i],key))}else vals=rows.map(x=>+x[key]||0);if(vals.length<2)return;let max=Math.max(...vals,1),min=Math.min(...vals,0),pad=18;ctx.strokeStyle='#22364c';ctx.lineWidth=1;for(let y of [0.25,.5,.75]){ctx.beginPath();ctx.moveTo(0,h*y);ctx.lineTo(w,h*y);ctx.stroke()}ctx.strokeStyle=color;ctx.lineWidth=2;ctx.beginPath();vals.forEach((v,i)=>{let x=pad+i*(w-pad*2)/(vals.length-1),y=h-pad-(v-min)*(h-pad*2)/(max-min||1);i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.stroke()}
function donut(id,parts){let t=parts.reduce((a,b)=>a+b[0],0)||1,a=0,s=[];for(let [v,c] of parts){let p=v/t*100;s.push(`${c} ${a}% ${a+p}%`);a+=p}document.getElementById(id).style.background=`conic-gradient(${s.join(',')})`}
async function dashboard(id=NODE){let ns=await A('/api/nodes');if(!ns.length){main.innerHTML='<h2>Nenhum DNS cadastrado</h2>';return}NODE=id||ns[0].id;let n=ns.find(x=>x.id==NODE)||ns[0],s=await A('/api/nodes/'+NODE+'/snapshot'),rows=await A('/api/nodes/'+NODE+'/history?minutes='+MIN),st=s.metrics?.stats||{},sy=s.system||{},hl=s.health||{},last=rows.at(-1)||{},prev=rows.at(-2)||last,qps=rows.length>1?rate(prev,last,'q'):0,v4=rows.length>1?rate(prev,last,'ipv4'):0,v6=rows.length>1?rate(prev,last,'ipv6'):0,h=+st['total.num.cachehits']||0,m=+st['total.num.cachemiss']||0,tot=h+m,no=+st['num.answer.rcode.NOERROR']||0,nx=+st['num.answer.rcode.NXDOMAIN']||0,rf=+st['num.answer.rcode.REFUSED']||0,sf=+st['num.answer.rcode.SERVFAIL']||0,nd=+st['num.answer.rcode.nodata']||0,sec=+st['num.answer.secure']||0,ans=no+nx+rf+sf+nd;
main.innerHTML=`<div class=top><div><h2 style='margin:0'>Visão geral</h2><span class=mut>${n.name} · ${n.role}</span></div><div class=topctrl><select class=ctl onchange='NODE=+this.value;dashboard()'>${ns.map(x=>`<option value=${x.id} ${x.id==NODE?'selected':''}>${x.name} (${x.role})</option>`).join('')}</select><select class=ctl onchange='MIN=+this.value;dashboard()'><option value=30 ${MIN==30?'selected':''}>Últimos 30 minutos</option><option value=60 ${MIN==60?'selected':''}>Última hora</option><option value=360 ${MIN==360?'selected':''}>6 horas</option><option value=1440 ${MIN==1440?'selected':''}>24 horas</option></select><button onclick='dashboard()'>↻ Atualizar</button><span class=pill>${s.ok&&hl.unbound_active?'ONLINE':'OFFLINE'}</span></div></div>
<div class=kpis>${[['NOERROR',no,'green'],['NXDOMAIN',nx,'blue'],['REFUSED',rf,'yellow'],['SERVFAIL',sf,'red'],['NODATA',nd,'purple'],['SECURE (DNSSEC)',sec,'cyan']].map(x=>`<div class='card k'><div class='${x[2]} title'>${x[0]}</div><div class=n>${F(x[1],0)}</div><div class='p ${x[2]}'>${F(pct(x[1],ans))}%</div></div>`).join('')}</div>
<div class='g g2'><div class=panel><div class=title>CONSULTAS IPv4 (QPS)</div><div class=mut>Total por segundo · atual <b class=red>${F(v4)} QPS</b></div><canvas id=cv4></canvas></div><div class=panel><div class=title>CONSULTAS IPv6 (QPS)</div><div class=mut>Total por segundo · atual <b class=yellow>${F(v6)} QPS</b></div><canvas id=cv6></canvas></div></div>
<div class='g g4'><div class=panel><div class=title>CPU</div><div class='big blue'>${F(sy.cpu_percent)}%</div><canvas id=ccpu></canvas></div><div class=panel><div class=title>MEMÓRIA</div><div class='big purple'>${F(sy.ram_percent)}%</div><canvas id=cram></canvas></div><div class=panel><div class=title>CARGA DO SISTEMA</div><div class='big cyan'>${F((sy.loadavg||[])[0])}</div><canvas id=cload></canvas></div><div class=panel><div class=title>LATÊNCIA DE RECURSÃO</div><div class='big yellow'>${F((+st['total.recursion.time.median']||0)*1000)} ms</div><canvas id=clat></canvas></div></div>
<div class='g g3'><div class=panel><div class=title>CACHE HIT / MISS</div><div class='big green'>${F(pct(h,tot))}%</div><div id=dcache class=donut></div><div class=metric><span>Cache Hits</span><b>${F(h,0)}</b></div><div class=metric><span>Cache Misses</span><b>${F(m,0)}</b></div></div><div class=panel><div class=title>DISTRIBUIÇÃO DE RESPOSTAS</div><div id=dresp class=donut></div>${[['NOERROR',no,'green'],['NXDOMAIN',nx,'blue'],['NODATA',nd,'purple'],['REFUSED',rf,'yellow'],['SERVFAIL',sf,'red']].map(x=>`<div class=metric><span class=${x[2]}>● ${x[0]}</span><b>${F(pct(x[1],ans))}%</b></div>`).join('')}</div><div class=panel><div class=title>OUTRAS MÉTRICAS</div><div class=metric><span>Consultas totais</span><b>${F(+st['total.num.queries']||0,0)}</b></div><div class=metric><span>QPS total</span><b>${F(qps)}</b></div><div class=metric><span>Requestlist max</span><b>${F(+st['total.requestlist.max']||0,0)}</b></div><div class=metric><span>Uptime Unbound</span><b class=green>${uptime(+st['time.up']||0)}</b></div><hr style='border-color:#24364e'><div class=title>ESTADO DO UNBOUND</div><div class=metric><span>Serviço</span><b class=green>${hl.unbound_active?'Ativo':'Falha'}</b></div><div class=metric><span>Recursão</span><b class=green>${hl.tests?.recursive_ok?'Ativa':'Falha'}</b></div><div class=metric><span>DNSSEC (AD)</span><b class=green>${hl.tests?.dnssec_ad?'Ativo':'Verificar'}</b></div></div></div>
<div class=tools><div class=panel><div class=title>AÇÕES RÁPIDAS</div><div class=actions><button onclick="act(${NODE},'reload_keep_cache')">↻ Reload</button><button onclick="act(${NODE},'restart')">⟳ Restart</button><button onclick="act(${NODE},'flush_all')">🗑 Flush Cache</button><button onclick='logs(${NODE})'>▣ Logs</button><button onclick='trouble(${NODE},0)'>🔧 Troubleshooting</button><button onclick='trouble(${NODE},1)'>⚙ Profundo</button></div></div><div class=panel><div class=title>TESTE DE DOMÍNIO / ACL</div><div class=row><input id=tdomain placeholder='ex: google.com'><button onclick='domainTest(${NODE},0)'>Testar</button><button onclick='domainTest(${NODE},1)'>Profundo</button></div><div class=row style='margin-top:8px'><input id=cidr placeholder='ex: 100.64.0.0/10'><select id=aa><option>allow</option><option>deny</option><option>refuse</option></select><button onclick="acl(${NODE},'add')">Adicionar</button><button onclick="acl(${NODE},'remove')">Remover</button></div></div><div class=panel><div class=title>PARÂMETROS SEGUROS</div><div class=row><input id=o placeholder=prefetch><input id=v placeholder=yes><button onclick='opt(${NODE})'>Aplicar</button></div><p><button onclick='cfg(${NODE})'>Editor avançado</button></p></div></div>`;
chart('cv4',rows,'ipv4','#ff4057',true);chart('cv6',rows,'ipv6','#ffb000',true);chart('ccpu',rows,'cpu','#2196f3');chart('cram',rows,'ram','#b54cff');chart('cload',rows,'load1','#19d3c5');chart('clat',rows,'lat','#ff8a18');donut('dcache',[[h,'#43d04f'],[m,'#ff4057']]);donut('dresp',[[no,'#43d04f'],[nx,'#2196f3'],[nd,'#b54cff'],[rf,'#ffb000'],[sf,'#ff4057']]);foot.innerHTML=`<span class=green>● ${n.name} (${n.role})</span><span>${n.host}:${n.port}</span><span>Coleta: 10 segundos</span><span>Painel v${s.panel_version||'2.0'}</span>`;clearTimeout(REF);REF=setTimeout(()=>dashboard(),10000)}
async function servers(){let ns=await A('/api/nodes');main.innerHTML='<h2>Servidores</h2><div class=kpis>'+ns.map(n=>`<div class='card k' onclick='NODE=${n.id};dashboard()' style='cursor:pointer'><div class=title>${n.name}</div><div class=mut>${n.role}</div><div>${n.host}:${n.port}</div></div>`).join('')+'</div>'}
async function audit(){let x=await A('/api/audits');main.innerHTML='<button onclick=dashboard()>← Voltar</button><h2>Auditoria</h2><pre></pre>';document.querySelector('pre').textContent=JSON.stringify(x,null,2)}function showManage(){dashboard()}
async function act(i,a){if(confirm('Executar '+a+'?')){await A('/api/nodes/'+i+'/action',{method:'POST',body:JSON.stringify({action:a})});dashboard()}}async function opt(i){if(confirm('Aplicar alteração com backup e rollback automático?')){await A('/api/nodes/'+i+'/option',{method:'POST',body:JSON.stringify({option:o.value,value:v.value})});dashboard()}}async function acl(i,x){await A('/api/nodes/'+i+'/acl/'+x,{method:'POST',body:JSON.stringify({cidr:cidr.value,action:aa.value})});alert('OK')}
async function domainTest(i,d){let domain=(tdomain.value||'').trim().toLowerCase().replace(/^https?:\/\//,'').split('/')[0];if(!domain)return alert('Digite um domínio');main.innerHTML='<button onclick=dashboard()>← Voltar</button><h2>Diagnóstico: '+domain+'</h2><pre>Executando...</pre>';try{let x=await A('/api/nodes/'+i+'/troubleshooting?deep='+d+'&domain='+encodeURIComponent(domain));document.querySelector('pre').textContent=x.output}catch(e){document.querySelector('pre').textContent=e}}
async function trouble(i,d){main.innerHTML='<button onclick=dashboard()>← Voltar</button><h2>Troubleshooting</h2><pre>Executando...</pre>';try{let x=await A('/api/nodes/'+i+'/troubleshooting?deep='+d);document.querySelector('pre').textContent=x.output}catch(e){document.querySelector('pre').textContent=e}}async function logs(i){let x=await A('/api/nodes/'+i+'/logs');main.innerHTML='<button onclick=dashboard()>← Voltar</button><h2>Logs</h2><pre></pre>';document.querySelector('pre').textContent=x.logs}
async function cfg(i){let x=await A('/api/nodes/'+i+'/config');main.innerHTML='<button onclick=dashboard()>← Voltar</button><h2>Configuração avançada</h2><p class=mut>Ao salvar: backup → checkconf → restart → teste DNS/DNSSEC → rollback em falha.</p><div class=editor><textarea id=c></textarea></div><p><button onclick="savecfg('+i+')">Validar e aplicar</button></p>';c.value=x.content}async function savecfg(i){if(confirm('Aplicar configuração completa?')){await A('/api/nodes/'+i+'/config',{method:'POST',body:JSON.stringify({content:c.value})});alert('Configuração aplicada');dashboard()}}
dashboard();
</script></body></html>"""
