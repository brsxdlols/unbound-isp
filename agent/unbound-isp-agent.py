import os, re, time, json, shutil, socket, tarfile, subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional
import psutil
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

CONF=Path("/etc/unbound/unbound.conf")
BACKUPS=Path("/var/lib/unbound-isp/backups")
NODE=os.getenv("UNBOUND_ISP_NODE",socket.gethostname())
ROLE=os.getenv("UNBOUND_ISP_ROLE","DNS")
API_KEY=os.environ["UNBOUND_ISP_API_KEY"]
ALLOWED={x.strip() for x in os.getenv("UNBOUND_ISP_ALLOWED_IPS","127.0.0.1").split(",") if x.strip()}
AUDIT=Path("/var/log/unbound-isp/agent-audit.log")

app=FastAPI(title="Unbound ISP Agent",version="1.0",docs_url=None,redoc_url=None)

SAFE_OPTIONS={
"num-threads","so-reuseport","outgoing-range","num-queries-per-thread","so-rcvbuf","so-sndbuf",
"msg-cache-size","rrset-cache-size","msg-cache-slabs","rrset-cache-slabs","infra-cache-slabs",
"key-cache-slabs","infra-cache-numhosts","cache-max-ttl","cache-min-ttl","prefetch","prefetch-key",
"serve-expired","serve-expired-ttl","serve-expired-client-timeout","serve-expired-reply-ttl",
"aggressive-nsec","minimal-responses","rrset-roundrobin","qname-minimisation","harden-glue",
"harden-dnssec-stripped","harden-below-nxdomain","hide-identity","hide-version","edns-buffer-size",
"max-udp-size","udp-connect","statistics-interval","extended-statistics","statistics-cumulative",
"verbosity","ratelimit","ip-ratelimit"
}

class OptionChange(BaseModel):
    option:str
    value:str
class Action(BaseModel):
    action:str
class RawConfig(BaseModel):
    content:str
class Rollback(BaseModel):
    backup_id:str
class ACLChange(BaseModel):
    cidr:str
    action:str="allow"

def log(action,detail,result):
    AUDIT.parent.mkdir(parents=True,exist_ok=True)
    with AUDIT.open("a") as f:
        f.write(json.dumps({"ts":int(time.time()),"node":NODE,"action":action,"detail":detail,"result":result})+"\n")

def auth(req,key):
    peer=req.client.host if req.client else ""
    if peer not in ALLOWED and peer not in ("127.0.0.1","::1"):
        raise HTTPException(403,"IP não autorizado")
    if key!=API_KEY:
        raise HTTPException(401,"chave inválida")

def run(cmd,timeout=30):
    p=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
    return p.returncode,p.stdout.strip()

def backup():
    BACKUPS.mkdir(parents=True,exist_ok=True)
    bid=datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    out=BACKUPS/f"{bid}.tar.gz"
    with tarfile.open(out,"w:gz") as t:
        t.add("/etc/unbound",arcname="etc/unbound")
    return bid

def restore(bid):
    if not re.fullmatch(r"\d{8}-\d{6}-\d{6}",bid):
        raise RuntimeError("backup inválido")
    src=BACKUPS/f"{bid}.tar.gz"
    if not src.exists(): raise RuntimeError("backup inexistente")
    tmp=Path("/tmp/unbound-isp-restore")
    rescue=Path("/tmp/unbound-isp-rescue")
    shutil.rmtree(tmp,ignore_errors=True); shutil.rmtree(rescue,ignore_errors=True)
    tmp.mkdir()
    with tarfile.open(src,"r:gz") as t:
        for m in t.getmembers():
            rp=Path(m.name)
            if rp.is_absolute() or ".." in rp.parts: raise RuntimeError("backup inseguro")
        t.extractall(tmp)
    shutil.copytree("/etc/unbound",rescue)
    shutil.rmtree("/etc/unbound")
    shutil.copytree(tmp/"etc/unbound","/etc/unbound")
    rc,out=run(["unbound-checkconf",str(CONF)])
    if rc:
        shutil.rmtree("/etc/unbound"); shutil.copytree(rescue,"/etc/unbound")
        raise RuntimeError(out)
    rc,out=run(["systemctl","restart","unbound"])
    if rc:
        shutil.rmtree("/etc/unbound"); shutil.copytree(rescue,"/etc/unbound")
        run(["systemctl","restart","unbound"])
        raise RuntimeError(out)

def dns_test():
    result={}
    rc,out=run(["dig","@127.0.0.1","cloudflare.com","A","+dnssec","+time=3","+tries=1"],8)
    result["recursive_ok"]=rc==0 and "status: NOERROR" in out
    result["dnssec_ad"]=bool(re.search(r"flags:.*\bad\b",out))
    m=re.search(r"Query time:\s+(\d+)\s+msec",out)
    result["query_ms"]=int(m.group(1)) if m else None
    rc,out=run(["dig","@127.0.0.1","dnssec-failed.org","A","+dnssec","+time=3","+tries=1"],8)
    result["dnssec_bogus_servfail"]="status: SERVFAIL" in out
    return result

def stats():
    rc,out=run(["unbound-control","-c",str(CONF),"stats_noreset"],15)
    if rc:return {},out
    d={}
    for line in out.splitlines():
        if "=" in line:
            k,v=line.split("=",1);d[k.strip()]=v.strip()
    return d,None

def server_block(lines):
    start=None; end=len(lines)
    for i,l in enumerate(lines):
        if re.match(r"^\s*server\s*:\s*(?:#.*)?$",l):
            start=i
            for j in range(i+1,len(lines)):
                if lines[j] and not lines[j].startswith((" ","\t","#","\n")) and re.match(r"^[A-Za-z0-9_-]+\s*:",lines[j]):
                    end=j;break
            break
    if start is None: raise RuntimeError("bloco server não encontrado")
    return start,end

def set_option(opt,val):
    if opt not in SAFE_OPTIONS: raise RuntimeError("opção não autorizada")
    lines=CONF.read_text().splitlines(True); start,end=server_block(lines)
    pat=re.compile(r"^(\s*)"+re.escape(opt)+r"\s*:")
    for i in range(start+1,end):
        m=pat.match(lines[i])
        if m:
            lines[i]=f"{m.group(1) or '    '}{opt}: {val}\n";break
    else: lines.insert(start+1,f"    {opt}: {val}\n")
    CONF.write_text("".join(lines))

def change_acl(cidr,action,remove=False):
    if not re.fullmatch(r"[0-9A-Fa-f:.]+/\d{1,3}",cidr): raise RuntimeError("CIDR inválido")
    if action not in ("allow","deny","refuse","allow_snoop"): raise RuntimeError("ação ACL inválida")
    lines=CONF.read_text().splitlines(True); start,end=server_block(lines)
    target=f"access-control: {cidr} {action}"
    if remove:
        lines=[l for l in lines if target not in l]
    else:
        if not any(target in l for l in lines):
            lines.insert(start+1,f"    {target}\n")
    CONF.write_text("".join(lines))

def apply_and_test(bid):
    rc,out=run(["unbound-checkconf",str(CONF)])
    if rc: restore(bid); raise RuntimeError("checkconf: "+out)
    rc,out=run(["systemctl","restart","unbound"])
    if rc: restore(bid); raise RuntimeError("restart: "+out)
    time.sleep(1)
    t=dns_test()
    if not t["recursive_ok"] or not t["dnssec_bogus_servfail"]:
        restore(bid); raise RuntimeError("teste pós-alteração falhou")
    return t

@app.get("/api/v1/troubleshooting")
def troubleshooting(request:Request,x_api_key:Optional[str]=Header(None),deep:int=0,domain:str=""):
    auth(request,x_api_key)
    cmd=["/root/unbound-troubleshooting.sh"]
    if deep: cmd.append("--deep")
    domain=domain.strip().lower().rstrip(".")
    if domain:
        if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",domain):
            raise HTTPException(400,"Domínio inválido")
        cmd += ["--domain",domain]
    rc,out=run(cmd,180 if deep else 120)
    return {"ok":rc==0,"deep":bool(deep),"domain":domain or None,"output":out}

@app.get("/api/v1/health")
def health(request:Request,x_api_key:Optional[str]=Header(None)):
    auth(request,x_api_key)
    rc,_=run(["systemctl","is-active","--quiet","unbound"])
    return {"node":NODE,"role":ROLE,"unbound_active":rc==0,"tests":dns_test()}

@app.get("/api/v1/system")
def system(request:Request,x_api_key:Optional[str]=Header(None)):
    auth(request,x_api_key); v=psutil.virtual_memory()
    return {"node":NODE,"role":ROLE,"cpu_count":psutil.cpu_count(),"cpu_percent":psutil.cpu_percent(.25),
            "loadavg":list(os.getloadavg()),"ram_total":v.total,"ram_used":v.used,"ram_percent":v.percent}

@app.get("/api/v1/metrics")
def metrics(request:Request,x_api_key:Optional[str]=Header(None)):
    auth(request,x_api_key); s,e=stats()
    return {"node":NODE,"role":ROLE,"timestamp":time.time(),"stats":s,"error":e}

@app.get("/api/v1/config")
def config(request:Request,x_api_key:Optional[str]=Header(None)):
    auth(request,x_api_key)
    return {"node":NODE,"content":CONF.read_text()}

@app.get("/api/v1/backups")
def backups(request:Request,x_api_key:Optional[str]=Header(None)):
    auth(request,x_api_key)
    return {"backups":[{"id":p.name[:-7],"size":p.stat().st_size,"mtime":p.stat().st_mtime}
                       for p in sorted(BACKUPS.glob("*.tar.gz"),reverse=True)[:50]]}

@app.get("/api/v1/logs")
def logs(request:Request,x_api_key:Optional[str]=Header(None),lines:int=150):
    auth(request,x_api_key); lines=max(20,min(lines,500))
    _,out=run(["journalctl","-u","unbound","-n",str(lines),"--no-pager"],15)
    return {"logs":out}

@app.post("/api/v1/unbound/option")
def option(data:OptionChange,request:Request,x_api_key:Optional[str]=Header(None)):
    auth(request,x_api_key); bid=backup()
    try:
        set_option(data.option,data.value); t=apply_and_test(bid)
        log("SET_OPTION",data.model_dump(),"OK")
        return {"ok":True,"backup_id":bid,"tests":t}
    except Exception as e:
        log("SET_OPTION",data.model_dump(),"ERRO")
        raise HTTPException(500,str(e))

@app.post("/api/v1/unbound/acl/add")
def acl_add(data:ACLChange,request:Request,x_api_key:Optional[str]=Header(None)):
    auth(request,x_api_key); bid=backup()
    try:
        change_acl(data.cidr,data.action,False); t=apply_and_test(bid)
        log("ACL_ADD",data.model_dump(),"OK"); return {"ok":True,"backup_id":bid,"tests":t}
    except Exception as e: log("ACL_ADD",data.model_dump(),"ERRO"); raise HTTPException(500,str(e))

@app.post("/api/v1/unbound/acl/remove")
def acl_remove(data:ACLChange,request:Request,x_api_key:Optional[str]=Header(None)):
    auth(request,x_api_key); bid=backup()
    try:
        change_acl(data.cidr,data.action,True); t=apply_and_test(bid)
        log("ACL_REMOVE",data.model_dump(),"OK"); return {"ok":True,"backup_id":bid,"tests":t}
    except Exception as e: log("ACL_REMOVE",data.model_dump(),"ERRO"); raise HTTPException(500,str(e))

@app.post("/api/v1/unbound/config")
def raw_config(data:RawConfig,request:Request,x_api_key:Optional[str]=Header(None)):
    auth(request,x_api_key)
    if len(data.content)>1024*1024: raise HTTPException(400,"configuração grande demais")
    bid=backup()
    try:
        CONF.write_text(data.content); t=apply_and_test(bid)
        log("RAW_CONFIG",{"bytes":len(data.content)},"OK")
        return {"ok":True,"backup_id":bid,"tests":t}
    except Exception as e: log("RAW_CONFIG",{"bytes":len(data.content)},"ERRO"); raise HTTPException(500,str(e))

@app.post("/api/v1/unbound/action")
def action(data:Action,request:Request,x_api_key:Optional[str]=Header(None)):
    auth(request,x_api_key)
    cmds={"reload":["unbound-control","-c",str(CONF),"reload"],
          "reload_keep_cache":["unbound-control","-c",str(CONF),"reload_keep_cache"],
          "restart":["systemctl","restart","unbound"],
          "flush_all":["unbound-control","-c",str(CONF),"flush_zone","."],
          "flush_infra":["unbound-control","-c",str(CONF),"flush_infra","all"]}
    if data.action not in cmds: raise HTTPException(400,"ação inválida")
    rc,out=run(cmds[data.action],40); log("ACTION",data.model_dump(),"OK" if rc==0 else "ERRO")
    if rc: raise HTTPException(500,out)
    return {"ok":True,"output":out}

@app.post("/api/v1/rollback")
def rollback(data:Rollback,request:Request,x_api_key:Optional[str]=Header(None)):
    auth(request,x_api_key)
    try: restore(data.backup_id); log("ROLLBACK",data.model_dump(),"OK")
    except Exception as e: log("ROLLBACK",data.model_dump(),"ERRO"); raise HTTPException(500,str(e))
    return {"ok":True}
