#!/bin/bash
set -u
DEEP=0
[ "${1:-}" = "--deep" ] && DEEP=1
DNS="127.0.0.1"
TS="$(date '+%d/%m/%Y %H:%M:%S')"
TMP="/tmp/unbound-troubleshooting.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT
OKC=0; WARNC=0; ERRC=0
G="\033[1;32m"; Y="\033[1;33m"; R="\033[1;31m"; B="\033[1;34m"; N="\033[0m"
ok(){ echo -e "${G}[ OK ]${N} $*"; OKC=$((OKC+1)); }
warn(){ echo -e "${Y}[AVISO]${N} $*"; WARNC=$((WARNC+1)); }
err(){ echo -e "${R}[ERRO]${N} $*"; ERRC=$((ERRC+1)); }
info(){ echo -e "${B}[INFO]${N} $*"; }
section(){ echo; echo "------------------------------------------------------------"; echo "$1"; echo "------------------------------------------------------------"; }
dig_ms(){ local server="$1" name="$2" type="${3:-A}" out ms; out="$(dig @"$server" "$name" "$type" +time=3 +tries=1 +stats 2>/dev/null || true)"; echo "$out" > "$TMP/dig.out"; if echo "$out"|grep -q 'status: NOERROR'; then ms="$(echo "$out"|awk '/Query time:/ {print $4;exit}')"; echo "${ms:-0}"; return 0; fi; return 1; }

echo "============================================================"
echo " UNBOUND ISP - TROUBLESHOOTING DNS"
echo " $TS"
echo " Modo: $([ "$DEEP" -eq 1 ] && echo PROFUNDO || echo NORMAL)"
echo "============================================================"

section "1 - SERVIÇO / PORTA 53"
if systemctl is-active --quiet unbound; then ok "Unbound está ATIVO."; else err "Unbound NÃO está ativo."; fi
if ss -lunp 2>/dev/null|grep ':53 '|grep -qi unbound; then ok "Unbound está escutando UDP/53."; else err "Unbound não encontrado em UDP/53."; fi
if ss -ltnp 2>/dev/null|grep ':53 '|grep -qi unbound; then ok "Unbound está escutando TCP/53."; else err "Unbound não encontrado em TCP/53."; fi

section "2 - RESOLUÇÃO LOCAL"
for d in google.com cloudflare.com registro.br microsoft.com; do
 if ms="$(dig_ms "$DNS" "$d" A)"; then
   if [ "${ms:-9999}" -le 250 ]; then ok "$d resolveu em ${ms} ms."; else warn "$d resolveu, mas demorou ${ms} ms."; fi
 else err "$d não resolveu corretamente pelo Unbound local."; fi
done

section "3 - CACHE"
CACHE_NAME="www.iana.org"
unbound-control flush "$CACHE_NAME" >/dev/null 2>&1 || true
H1="$(unbound-control stats_noreset 2>/dev/null|awk -F= '/^total.num.cachehits=/{print $2;exit}')"
T1="$(dig @"$DNS" "$CACHE_NAME" A +time=5 +tries=1 +stats 2>/dev/null|awk '/Query time:/ {print $4;exit}')"
T2="$(dig @"$DNS" "$CACHE_NAME" A +time=5 +tries=1 +stats 2>/dev/null|awk '/Query time:/ {print $4;exit}')"
H2="$(unbound-control stats_noreset 2>/dev/null|awk -F= '/^total.num.cachehits=/{print $2;exit}')"
echo "Primeira consulta : ${T1:-N/D} ms"
echo "Segunda consulta  : ${T2:-N/D} ms"
if [ -n "${H1:-}" ] && [ -n "${H2:-}" ] && awk "BEGIN{exit !($H2>$H1)}"; then ok "Cache hit aumentou: resposta armazenada e reutilizada."; else warn "Não foi possível confirmar aumento de cache hit."; fi
if [ -n "${T1:-}" ] && [ -n "${T2:-}" ] && [ "$T2" -le "$T1" ]; then ok "Segunda consulta foi igual ou mais rápida."; else warn "Segunda consulta não ficou mais rápida."; fi

section "4 - DNSSEC"
V="$(dig @"$DNS" cloudflare.com A +dnssec +time=3 +tries=1 2>/dev/null || true)"
if echo "$V"|grep -q 'status: NOERROR' && echo "$V"|grep -Eq 'flags:.*\bad\b'; then ok "DNSSEC válido: NOERROR + AD."; else err "Falha na validação DNSSEC válida."; fi
I="$(dig @"$DNS" dnssec-failed.org A +dnssec +time=3 +tries=1 2>/dev/null || true)"
if echo "$I"|grep -q 'status: SERVFAIL'; then ok "DNSSEC inválido recusado com SERVFAIL."; else err "DNSSEC inválido NÃO foi recusado como esperado."; fi

section "5 - RECURSÃO / FORWARD"
FW="$(grep -RniE '^[[:space:]]*(forward-zone:|forward-addr:|forward-host:)' /etc/unbound 2>/dev/null || true)"
if [ -z "$FW" ]; then ok "Nenhum forward-zone/forward-addr configurado."; ok "Configuração indica recursão própria."; else warn "Foram encontrados forwards:"; echo "$FW"; fi
if [ -s /var/lib/unbound/root.hints ]; then ok "root.hints/named.cache presente."; else warn "root.hints não encontrado."; fi
if grep -RqsE '^[[:space:]]*root-hints:' /etc/unbound 2>/dev/null; then ok "root-hints referenciado na configuração."; else warn "Diretiva root-hints não encontrada."; fi
if grep -RqsE '^[[:space:]]*auth-zone:' /etc/unbound 2>/dev/null; then ok "auth-zone da raiz configurada."; else info "auth-zone não encontrada."; fi

section "6 - ESTATÍSTICAS UNBOUND"
S="$(unbound-control stats_noreset 2>/dev/null || true)"
Q="$(echo "$S"|awk -F= '/^total.num.queries=/{print $2;exit}')"; H="$(echo "$S"|awk -F= '/^total.num.cachehits=/{print $2;exit}')"; M="$(echo "$S"|awk -F= '/^total.num.cachemiss=/{print $2;exit}')"; TO="$(echo "$S"|awk -F= '/^total.num.queries_timed_out=/{print $2;exit}')"; RQ="$(echo "$S"|awk -F= '/^total.requestlist.current.all=/{print $2;exit}')"; RM="$(echo "$S"|awk -F= '/^total.requestlist.max=/{print $2;exit}')"; LAT="$(echo "$S"|awk -F= '/^total.recursion.time.median=/{print $2;exit}')"
echo "Consultas        : ${Q:-N/D}"; echo "Cache hits       : ${H:-N/D}"; echo "Cache misses     : ${M:-N/D}"; echo "Timeouts         : ${TO:-N/D}"; echo "Requestlist atual: ${RQ:-N/D}"; echo "Requestlist máx. : ${RM:-N/D}"; echo "Recursion median : ${LAT:-N/D} s"
if [ -n "${H:-}" ] && [ -n "${M:-}" ]; then RATE="$(awk "BEGIN{t=$H+$M;if(t>0)printf \"%.2f\",($H/t)*100;else print 0}")"; echo "Cache hit rate   : ${RATE}%"; fi
if [ -n "${RQ:-}" ] && awk "BEGIN{exit !($RQ>100)}"; then warn "Requestlist atual elevada: $RQ."; else ok "Fila atual do Unbound sem sinal de saturação."; fi
if [ -n "${LAT:-}" ] && awk "BEGIN{exit !($LAT>0.250)}"; then warn "Recursion median elevada: ${LAT}s."; else ok "Latência mediana de recursão normal."; fi

section "7 - SISTEMA"
CPU="$(LC_ALL=C top -bn1 2>/dev/null|awk '/Cpu\(s\)/{print 100-$8;exit}')"; RAM="$(free|awk '/Mem:/{printf "%.1f",($3/$2)*100}')"; SWAP="$(free|awk '/Swap:/{if($2>0)printf "%.1f",($3/$2)*100;else print "0"}')"; LOAD="$(awk '{print $1}' /proc/loadavg)"
echo "CPU  : ${CPU:-N/D}%"; echo "RAM  : ${RAM:-N/D}%"; echo "SWAP : ${SWAP:-N/D}%"; echo "LOAD : ${LOAD:-N/D}"
if [ -n "${RAM:-}" ] && awk "BEGIN{exit !($RAM>90)}"; then warn "Uso de RAM acima de 90%."; else ok "Memória sem saturação crítica."; fi

section "8 - REDE / UDP"
if command -v nstat >/dev/null 2>&1; then NSTAT="$(nstat -az 2>/dev/null|grep -E 'Udp(InErrors|RcvbufErrors|SndbufErrors|NoPorts)' || true)"; echo "$NSTAT"; BAD="$(echo "$NSTAT"|awk '$2+0>0{c++}END{print c+0}')"; if [ "${BAD:-0}" -gt 0 ]; then warn "Há contadores UDP de erro diferentes de zero; verificar evolução."; else ok "Nenhum contador UDP crítico identificado."; fi; else info "nstat não disponível."; fi

section "9 - COMPARAÇÃO DE CONECTIVIDADE"
for target in "LOCAL:$DNS" "CLOUDFLARE:1.1.1.1" "GOOGLE:8.8.8.8"; do name="${target%%:*}"; srv="${target#*:}"; if ms="$(dig_ms "$srv" example.com A)"; then echo "$name = ${ms} ms"; else echo "$name = FALHOU"; fi; done
info "DNS externos são usados SOMENTE como comparação; não são configurados como forwarders."

if [ "$DEEP" -eq 1 ]; then
 section "10 - ROOT / TLD / TCP (PROFUNDO)"
 ROOTIP="$(awk 'toupper($4)=="A"{print $5;exit}' /var/lib/unbound/root.hints 2>/dev/null || true)"
 if [ -n "$ROOTIP" ]; then if dig @"$ROOTIP" . NS +norecurse +time=3 +tries=1 >/dev/null 2>&1; then ok "Root server $ROOTIP acessível diretamente."; else warn "Falha consultando root server $ROOTIP diretamente."; fi; fi
 if dig @"$DNS" com. NS +dnssec +time=3 +tries=1 >/dev/null 2>&1; then ok "Delegação .COM acessível."; else err "Falha consultando .COM."; fi
 if dig @"$DNS" br. NS +dnssec +time=3 +tries=1 >/dev/null 2>&1; then ok "Delegação .BR acessível."; else err "Falha consultando .BR."; fi
 if dig @"$DNS" cloudflare.com A +tcp +time=3 +tries=1 >/dev/null 2>&1; then ok "Resolução via TCP/53 funcionando."; else err "Falha na resolução via TCP/53."; fi
fi

section "RESULTADO"
SCORE=$((100 - ERRC*20 - WARNC*5)); [ "$SCORE" -lt 0 ] && SCORE=0
echo "OK     : $OKC"; echo "AVISOS : $WARNC"; echo "ERROS  : $ERRC"; echo; echo "SAÚDE DO DNS: ${SCORE}/100"
if [ "$ERRC" -eq 0 ] && [ "$WARNC" -eq 0 ]; then ok "Nenhum problema detectado."; elif [ "$ERRC" -eq 0 ]; then warn "DNS operacional, porém há pontos de atenção."; else err "Foram detectadas falhas; investigue os itens ERRO."; fi
echo; echo "Normal : /root/unbound-troubleshooting.sh"; echo "Profundo: /root/unbound-troubleshooting.sh --deep"; echo "============================================================"
