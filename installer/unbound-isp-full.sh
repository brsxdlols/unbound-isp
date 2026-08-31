#!/bin/bash
set -euo pipefail
# ============================================================
# UNBOUND ISP FULL 1.4
# Instalador / Gerenciador único: DNS1, DNS2 e Painel opcional
# Debian 11/12
# ============================================================
ETC=/etc/unbound-isp
BASE=/opt/unbound-isp
DATA=/var/lib/unbound-isp
LOG=/var/log/unbound-isp
CONF=/etc/unbound/unbound.conf
AGENT_PORT=9443
TROUBLESHOOTING_REF="c85e77e01a52cbaea7b7a8b6f7abba255e7691b2"
mkdir -p "$ETC" "$BASE" "$DATA" "$LOG" "$DATA/backups"

install_troubleshooting() {
    local url="https://raw.githubusercontent.com/brsxdlols/unbound-isp/${TROUBLESHOOTING_REF}/troubleshooting/unbound-troubleshooting.sh"
    if ! curl -fsSL "$url" -o /root/unbound-troubleshooting.sh; then
        echo "ERRO: não foi possível baixar o troubleshooting estável do projeto."
        return 1
    fi
    chmod +x /root/unbound-troubleshooting.sh
    printf '%s\n' "$TROUBLESHOOTING_REF" > "$ETC/troubleshooting.version"
}

die(){ echo "ERRO: $*" >&2; exit 1; }
yn(){ local q="$1" d="${2:-n}" r; if [ "$d" = s ];then read -r -p "$q [S/n]: " r;r="${r:-s}";else read -r -p "$q [s/N]: " r;r="${r:-n}";fi;[[ "$r" =~ ^[Ss]$ ]]; }
pause(){ read -r -p "ENTER para continuar..." _; }
[ "$(id -u)" -eq 0 ] || die "execute como root"

packages(){
 apt-get update
 apt-get install -y unbound unbound-anchor dnsutils dnstop python3 python3-venv python3-pip curl openssl iproute2 procps sqlite3 ca-certificates
}

backup_unbound(){
 local t="$(date +%Y%m%d-%H%M%S)"
 [ -d /etc/unbound ] && tar -C / -czf "$DATA/backups/pre-$t.tar.gz" etc/unbound || true
}

ensure_control(){
 grep -RqsE '^[[:space:]]*control-enable:[[:space:]]*yes' /etc/unbound 2>/dev/null && return 0
 cat >> "$CONF" <<'EOF'

remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-use-cert: no
EOF
}

create_core(){
 local role="$1" node="$2"
 packages
 install_troubleshooting
 backup_unbound
 if [ -s "$CONF" ] && unbound-checkconf "$CONF" >/dev/null 2>&1;then
   echo "Unbound existente e válido detectado."
   if yn "Manter configuração atual?" s;then ensure_control
   else create_fresh_config
   fi
 else create_fresh_config
 fi
 unbound-checkconf "$CONF" || die "Unbound inválido"
 mkdir -p /etc/systemd/system/unbound.service.d
 cat > /etc/systemd/system/unbound.service.d/limits.conf <<'EOF'
[Service]
LimitNOFILE=65536
EOF
 cat > /etc/sysctl.d/99-unbound-isp.conf <<'EOF'
net.core.rmem_max=16777216
net.core.wmem_max=16777216
EOF
 sysctl --system >/dev/null || true
 systemctl daemon-reload;systemctl enable unbound;systemctl restart unbound
 cat > "$ETC/node.conf" <<EOF
ROLE=$role
NODE_NAME=$node
PANEL_INTEGRATED=no
EOF
 install_agent "$role" "$node"
 if yn "Apontar /etc/resolv.conf para 127.0.0.1?" s;then
 cat > /etc/resolv.conf <<'EOF'
nameserver 127.0.0.1
options timeout:1 attempts:3
EOF
 fi
}

create_fresh_config(){
 local cpu="$(nproc)" memkb="$(awk '/MemTotal/{print $2}' /proc/meminfo)"
 local memmb=$((memkb/1024)) msg=$((memmb/16)) rr=$((memmb/8))
 ((msg<64))&&msg=64;((rr<128))&&rr=128
 local ip4="" ip6="" do6=no x
 echo
 while true;do
   ip4=""
   echo "=== Redes IPv4 permitidas ==="
   echo "1 - Informar redes/blocos manualmente"
   echo "2 - Liberar consultas IPv4 para QUALQUER origem (0.0.0.0/0)"
   read -r -p "Escolha [1]: " mode4
   mode4="${mode4:-1}"

   if [ "$mode4" = "2" ];then
     echo
     echo "ATENÇÃO: 0.0.0.0/0 deixa o resolvedor aberto para qualquer IPv4."
     echo "Se a porta 53 estiver acessível pela Internet, isso pode gerar abuso."
     if yn "Confirma liberar 0.0.0.0/0?" n;then
       ip4='    access-control: 0.0.0.0/0 allow'$'\n'
     else
       mode4="1"
     fi
   fi

   if [ "$mode4" = "1" ];then
     echo
     while true;do
       read -r -p "Bloco IPv4 permitido [ENTER termina]: " x
       [ -z "$x" ]&&break
       ip4+="    access-control: $x allow"$'\n'
     done
   fi

   echo
   echo "===== Redes IPv4 informadas ====="
   if [ -n "$ip4" ];then
     printf "%s" "$ip4" | sed 's/^[[:space:]]*access-control:[[:space:]]*/ - /; s/[[:space:]]allow$//'
   else
     echo " - Nenhuma rede adicional informada"
   fi

   if yn "As redes IPv4 acima estão corretas?" s;then break;fi
   echo "Vamos informar novamente."
 done

 if yn "Habilitar IPv6?" n;then
   do6=yes
   while true;do
     ip6=""
     echo
     while true;do
       read -r -p "Bloco IPv6 permitido [ENTER termina]: " x
       [ -z "$x" ]&&break
       ip6+="    access-control: $x allow"$'\n'
     done
     echo
     echo "===== Redes IPv6 informadas ====="
     if [ -n "$ip6" ];then
       printf "%s" "$ip6" | sed 's/^[[:space:]]*access-control:[[:space:]]*/ - /; s/[[:space:]]allow$//'
     else
       echo " - Nenhuma rede IPv6 adicional informada"
     fi
     if yn "As redes IPv6 acima estão corretas?" s;then break;fi
     echo "Vamos informar novamente."
   done
 fi
 mkdir -p /var/lib/unbound
 unbound-anchor -a /var/lib/unbound/root.key || true
 chown -R unbound:unbound /var/lib/unbound
 cat > "$CONF" <<EOF
server:
    use-syslog: yes
    verbosity: 1
    interface: 0.0.0.0
    interface: 127.0.0.1
    interface-automatic: yes
    access-control: 127.0.0.0/8 allow
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 192.168.0.0/16 allow
    access-control: 100.64.0.0/10 allow
    access-control: 198.18.0.0/15 allow
$ip4$ip6    do-ip4: yes
    do-ip6: $do6
    do-udp: yes
    do-tcp: yes
    num-threads: $cpu
    so-reuseport: yes
    outgoing-range: 4096
    num-queries-per-thread: 2048
    so-rcvbuf: 8m
    so-sndbuf: 8m
    msg-cache-size: ${msg}m
    rrset-cache-size: ${rr}m
    cache-max-ttl: 86400
    prefetch: yes
    prefetch-key: yes
    serve-expired: yes
    serve-expired-ttl: 86400
    serve-expired-client-timeout: 1800
    serve-expired-reply-ttl: 30
    aggressive-nsec: yes
    minimal-responses: yes
    rrset-roundrobin: yes
    qname-minimisation: yes
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    edns-buffer-size: 1232
    max-udp-size: 1232
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    statistics-interval: 0
    extended-statistics: yes
    statistics-cumulative: yes

remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-use-cert: no

auth-zone:
    name: "."
    master: "lax.xfr.dns.icann.org"
    master: "iad.xfr.dns.icann.org"
    fallback-enabled: yes
    for-downstream: no
    for-upstream: yes
    zonefile: "/var/lib/unbound/root.zone"
EOF
}

install_agent(){
 local role="$1" node="$2" dir="$BASE/agent"
 mkdir -p "$dir" "$ETC/pki"
 python3 -m venv "$dir/venv"
 "$dir/venv/bin/pip" install -q --upgrade pip
 "$dir/venv/bin/pip" install -q fastapi uvicorn psutil
 if ! curl -fsSL "https://raw.githubusercontent.com/brsxdlols/unbound-isp/main/agent/unbound-isp-agent.py" -o "$dir/agent.py"; then
  die "Falha ao baixar Agent do repositório"
 fi
 install_troubleshooting
 local key="$(openssl rand -hex 32)"
 cat > "$ETC/agent.env" <<EOF
UNBOUND_ISP_NODE=$node
UNBOUND_ISP_ROLE=$role
UNBOUND_ISP_API_KEY=$key
UNBOUND_ISP_ALLOWED_IPS=127.0.0.1
EOF
 chmod 600 "$ETC/agent.env"
 openssl req -x509 -newkey rsa:3072 -nodes -keyout "$ETC/pki/agent.key" -out "$ETC/pki/agent.crt" -days 825 -sha256 -subj "/CN=$node" >/dev/null 2>&1
 write_agent_service bootstrap
 systemctl daemon-reload;systemctl enable --now unbound-isp-agent
 echo "Chave Agent: $key"
}

write_agent_service(){
 local mode="$1" extra=""
 if [ "$mode" = mtls ];then extra="--ssl-cert-reqs 2 --ssl-ca-certs $ETC/pki/ca.crt";fi
 cat > /etc/systemd/system/unbound-isp-agent.service <<EOF
[Unit]
Description=Unbound ISP Agent
After=network-online.target unbound.service
Wants=network-online.target
[Service]
Type=simple
EnvironmentFile=$ETC/agent.env
WorkingDirectory=$BASE/agent
ExecStart=$BASE/agent/venv/bin/uvicorn agent:app --host 0.0.0.0 --port $AGENT_PORT --ssl-keyfile $ETC/pki/agent.key --ssl-certfile $ETC/pki/agent.crt $extra --no-server-header
Restart=always
RestartSec=2
User=root
NoNewPrivileges=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
EOF
}

create_pki(){
 mkdir -p "$ETC/pki";chmod 700 "$ETC/pki"
 if [ ! -s "$ETC/pki/ca.key" ];then
   openssl genrsa -out "$ETC/pki/ca.key" 4096 >/dev/null 2>&1
   openssl req -x509 -new -key "$ETC/pki/ca.key" -sha256 -days 3650 -out "$ETC/pki/ca.crt" -subj "/CN=Unbound ISP Cluster CA" >/dev/null 2>&1
 fi
 if [ ! -s "$ETC/pki/controller.key" ];then
   openssl genrsa -out "$ETC/pki/controller.key" 3072 >/dev/null 2>&1
   openssl req -new -key "$ETC/pki/controller.key" -out /tmp/controller.csr -subj "/CN=unbound-isp-controller" >/dev/null 2>&1
   openssl x509 -req -in /tmp/controller.csr -CA "$ETC/pki/ca.crt" -CAkey "$ETC/pki/ca.key" -CAcreateserial -out "$ETC/pki/controller.crt" -days 825 -sha256 >/dev/null 2>&1
 fi
}

issue_local_agent_cert(){
 local node="$1"
 create_pki
 cat > /tmp/agent-san.cnf <<EOF
[req]
distinguished_name=dn
req_extensions=req_ext
prompt=no
[dn]
CN=$node
[req_ext]
subjectAltName=IP:127.0.0.1,DNS:localhost
EOF
 openssl genrsa -out "$ETC/pki/agent.key" 3072 >/dev/null 2>&1
 openssl req -new -key "$ETC/pki/agent.key" -out /tmp/agent.csr -config /tmp/agent-san.cnf >/dev/null 2>&1
 openssl x509 -req -in /tmp/agent.csr -CA "$ETC/pki/ca.crt" -CAkey "$ETC/pki/ca.key" -CAcreateserial -out "$ETC/pki/agent.crt" -days 825 -sha256 -extfile /tmp/agent-san.cnf -extensions req_ext >/dev/null 2>&1
 write_agent_service mtls
 sed -i 's|^UNBOUND_ISP_ALLOWED_IPS=.*|UNBOUND_ISP_ALLOWED_IPS=127.0.0.1|' "$ETC/agent.env"
 systemctl daemon-reload;systemctl restart unbound-isp-agent
}

install_panel(){
 packages
 install_troubleshooting
 if [ ! -f "$ETC/node.conf" ];then
   command -v unbound >/dev/null || die "Unbound não encontrado"
   read -r -p "Nome deste DNS1 [$(hostname)]: " N;N="${N:-$(hostname)}"
   cat > "$ETC/node.conf" <<EOF
ROLE=DNS1
NODE_NAME=$N
PANEL_INTEGRATED=yes
EOF
 fi
 . "$ETC/node.conf"
 [ "${ROLE:-}" = DNS1 ] || die "Painel central deve ser instalado no DNS1"
 [ -f "$ETC/agent.env" ] || install_agent DNS1 "$NODE_NAME"
 create_pki
 issue_local_agent_cert "$NODE_NAME"
 local d="$BASE/dashboard" port user pass secret
 mkdir -p "$d"
 python3 -m venv "$d/venv"
 "$d/venv/bin/pip" install -q --upgrade pip
 "$d/venv/bin/pip" install -q fastapi uvicorn httpx python-multipart
 if ! curl -fsSL "https://raw.githubusercontent.com/brsxdlols/unbound-isp/main/dashboard/app.py" -o "$d/app.py"; then
  die "Falha ao baixar Dashboard do repositório"
 fi
 read -r -p "Porta HTTPS do painel [9080]: " port;port="${port:-9080}"
 read -r -p "Usuário administrador [admin]: " user;user="${user:-admin}"
 while true;do read -r -s -p "Senha do painel: " pass;echo;[ -n "$pass" ]&&break;done
 secret="$(openssl rand -hex 32)"
 local akey="$(awk -F= '/^UNBOUND_ISP_API_KEY=/' "$ETC/agent.env" | cut -d= -f2-)"
 export UNBOUND_ISP_DB="$DATA/dashboard.db" UNBOUND_ISP_SESSION_SECRET="$secret"
 "$d/venv/bin/python" - <<PY
import os,sys,time
sys.path.insert(0,"$d")
from app import init_db,create_user,db
init_db();create_user($(printf '%q' "$user"),$(printf '%q' "$pass"))
with db() as c:
 c.execute("INSERT OR REPLACE INTO nodes(name,host,port,api_key,role,enabled,allow_changes,created_at) VALUES(?,?,?,?,?,1,1,?)",
 ("$NODE_NAME","127.0.0.1",$AGENT_PORT,"$akey","DNS1",int(time.time())))
PY
 openssl req -x509 -newkey rsa:3072 -nodes -keyout "$ETC/pki/panel.key" -out "$ETC/pki/panel.crt" -days 825 -sha256 -subj "/CN=$NODE_NAME" >/dev/null 2>&1
 cat > "$ETC/dashboard.env" <<EOF
UNBOUND_ISP_DB=$DATA/dashboard.db
UNBOUND_ISP_SESSION_SECRET=$secret
EOF
 chmod 600 "$ETC/dashboard.env"
 cat > /etc/systemd/system/unbound-isp-dashboard.service <<EOF
[Unit]
Description=Unbound ISP Dashboard
After=network-online.target unbound-isp-agent.service
[Service]
Type=simple
EnvironmentFile=$ETC/dashboard.env
WorkingDirectory=$d
ExecStart=$d/venv/bin/uvicorn app:app --host 0.0.0.0 --port $port --ssl-keyfile $ETC/pki/panel.key --ssl-certfile $ETC/pki/panel.crt --no-server-header
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
 cat > "$ETC/panel.conf" <<EOF
INSTALLED=yes
WEB_PORT=$port
EOF
 systemctl daemon-reload;systemctl enable --now unbound-isp-dashboard
 echo;echo "Painel: https://$(hostname -I|awk '{print $1}'):$port"
 echo "Troubleshooting estável: $TROUBLESHOOTING_REF"
 if yn "Gerar código para integrar um DNS2 agora?" s;then generate_token;fi
}

generate_token(){
 [ -f "$ETC/panel.conf" ] || die "Painel não instalado"
 . "$ETC/panel.conf"
 local t="$(openssl rand -hex 16)"
 UNBOUND_ISP_DB="$DATA/dashboard.db" UNBOUND_ISP_SESSION_SECRET=x "$BASE/dashboard/venv/bin/python" - <<PY
import sqlite3,time
db=sqlite3.connect("$DATA/dashboard.db")
db.execute("INSERT INTO pair_tokens(token,expires,used) VALUES(?,?,0)",( "$t",int(time.time())+900));db.commit()
PY
 echo
 echo "============================================================"
 echo " CÓDIGO DE PAREAMENTO (válido por 15 minutos)"
 echo " $t"
 echo " Painel DNS1: https://$(hostname -I|awk '{print $1}'):$WEB_PORT"
 echo "============================================================"
}

pair_dns2(){
 [ -f "$ETC/node.conf" ] || die "DNS2 não configurado"
 . "$ETC/node.conf";[ "$ROLE" = DNS2 ] || die "execute no DNS2"
 local pip pport token myip name akey
 read -r -p "IP do DNS1/Painel: " pip
 read -r -p "Porta HTTPS do painel [9080]: " pport;pport="${pport:-9080}"
 read -r -p "Código de pareamento: " token
 read -r -p "IP deste DNS2 que o DNS1 acessará [$(hostname -I|awk '{print $1}')]: " myip;myip="${myip:-$(hostname -I|awk '{print $1}')}"
 name="${NODE_NAME:-$(hostname)}";akey="$(awk -F= '/^UNBOUND_ISP_API_KEY=/' "$ETC/agent.env"|cut -d= -f2-)"
 cat > /tmp/dns2-san.cnf <<EOF
[req]
distinguished_name=dn
req_extensions=req_ext
prompt=no
[dn]
CN=$name
[req_ext]
subjectAltName=IP:$myip,DNS:$name
EOF
 openssl genrsa -out "$ETC/pki/agent-new.key" 3072 >/dev/null 2>&1
 openssl req -new -key "$ETC/pki/agent-new.key" -out /tmp/dns2.csr -config /tmp/dns2-san.cnf >/dev/null 2>&1
 python3 - <<PY
import json,base64,ssl,urllib.request
d={"token":"$token","name":"$name","host":"$myip","port":$AGENT_PORT,"api_key":"$akey","csr_b64":base64.b64encode(open("/tmp/dns2.csr","rb").read()).decode()}
ctx=ssl._create_unverified_context()
r=urllib.request.urlopen(urllib.request.Request("https://$pip:$pport/api/pair/join",data=json.dumps(d).encode(),headers={"Content-Type":"application/json"}),context=ctx,timeout=15)
o=json.loads(r.read())
open("$ETC/pki/agent-new.crt","wb").write(base64.b64decode(o["cert_b64"]))
open("$ETC/pki/ca.crt","wb").write(base64.b64decode(o["ca_b64"]))
PY
 mv "$ETC/pki/agent-new.key" "$ETC/pki/agent.key";mv "$ETC/pki/agent-new.crt" "$ETC/pki/agent.crt"
 sed -i "s|^UNBOUND_ISP_ALLOWED_IPS=.*|UNBOUND_ISP_ALLOWED_IPS=$pip,127.0.0.1|" "$ETC/agent.env"
 write_agent_service mtls
 systemctl daemon-reload;systemctl restart unbound-isp-agent
 sed -i 's/^PANEL_INTEGRATED=.*/PANEL_INTEGRATED=yes/' "$ETC/node.conf"
 echo "PANEL_IP=$pip" >> "$ETC/node.conf"
 echo "Pareamento mTLS concluído."
}

audit(){
 clear;echo "===== AUDITORIA UNBOUND ====="
 command -v unbound >/dev/null || { echo "Unbound não instalado";pause;return; }
 unbound -V|head -8 || true;echo
 unbound-checkconf "$CONF" || true;echo
 systemctl --no-pager status unbound|head -15 || true;echo
 unbound-control stats_noreset 2>/dev/null|grep -E 'total.num.queries=|cachehits=|cachemiss=|queries_timed_out=|requestlist.max=|recursion.time.median=|mem.cache' || true
 echo;dig @127.0.0.1 cloudflare.com A +dnssec +time=3 +tries=1|grep -E 'status:|flags:|Query time:' || true
 echo;dig @127.0.0.1 dnssec-failed.org A +dnssec +time=3 +tries=1|grep 'status:' || true
 pause
}

diagnostic(){
 clear
 install_troubleshooting
 echo "Troubleshooting estável: $TROUBLESHOOTING_REF"
 echo "1 - Troubleshooting normal"
 echo "2 - Troubleshooting profundo"
 read -r -p "Opção [1]: " td; td="${td:-1}"
 if [ "$td" = "2" ];then /root/unbound-troubleshooting.sh --deep;else /root/unbound-troubleshooting.sh;fi
 pause
}

install_dns1(){
 clear;read -r -p "Nome DNS1 [$(hostname)]: " n;n="${n:-$(hostname)}";create_core DNS1 "$n"
 if yn "Instalar Painel Web agora?" n;then install_panel;else echo "Painel poderá ser instalado depois pela opção 4.";fi
 pause
}
install_dns2(){
 clear;read -r -p "Nome DNS2 [$(hostname)]: " n;n="${n:-$(hostname)}";create_core DNS2 "$n"
 if yn "Integrar este DNS2 com Painel Web DNS1 agora?" n;then pair_dns2;else echo "DNS2 instalado independente. Use opção 6 posteriormente.";fi
 pause
}
manage_panel(){
 clear
 if [ ! -f "$ETC/panel.conf" ];then echo "Painel não instalado.";pause;return;fi
 echo "1 - Status";echo "2 - Reiniciar painel";echo "3 - Gerar código para DNS2";echo "4 - Reinstalar troubleshooting estável";echo "0 - Voltar";read -r -p "Opção: " x
 case "$x" in 1) systemctl --no-pager status unbound-isp-dashboard|head -20||true;;2)systemctl restart unbound-isp-dashboard;echo OK;;3)generate_token;;4)install_troubleshooting;echo "Troubleshooting estável reinstalado: $TROUBLESHOOTING_REF";;esac
 pause
}
pair_menu(){
 [ -f "$ETC/node.conf" ] || die "Perfil DNS não encontrado";. "$ETC/node.conf"
 if [ "$ROLE" = DNS2 ];then pair_dns2
 elif [ "$ROLE" = DNS1 ];then generate_token
 else die "função desconhecida";fi
 pause
}

menu(){
 while true;do clear
 echo "============================================================"
 echo " UNBOUND ISP FULL 1.4 - INSTALADOR / GERENCIADOR"
 echo "============================================================"
 echo "1 - Instalar / Configurar DNS1 PRINCIPAL"
 echo "2 - Instalar / Configurar DNS2 SECUNDÁRIO"
 echo "3 - Auditar / Otimizar Unbound existente"
 echo "4 - Instalar PAINEL WEB em DNS1 existente"
 echo "5 - Gerenciar / Atualizar PAINEL WEB"
 echo "6 - Gerenciar Agent / Pareamento DNS2"
 echo "7 - Diagnóstico completo"
 echo "0 - Sair";echo
 read -r -p "Opção: " o
 case "$o" in 1)install_dns1;;2)install_dns2;;3)audit;;4)install_panel;pause;;5)manage_panel;;6)pair_menu;;7)diagnostic;;0)exit 0;;*)sleep 1;;esac
 done
}
menu
