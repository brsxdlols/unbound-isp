#!/bin/bash
set -u
DEEP=0
DOMAIN=""
while [ $# -gt 0 ]; do
    case "$1" in
        --deep) DEEP=1 ;;
        --domain) shift; DOMAIN="${1:-}" ;;
        *) echo "Parâmetro desconhecido: $1" >&2; exit 2 ;;
    esac
    shift
done
if [ -n "$DOMAIN" ] && ! [[ "$DOMAIN" =~ ^([A-Za-z0-9]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]; then
    echo "ERRO: domínio inválido: $DOMAIN" >&2
    exit 2
fi
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
get_nstat(){ nstat -az 2>/dev/null | awk -v k="$1" '$1==k{print $2+0;exit}'; }

echo "============================================================"
echo " UNBOUND ISP - TROUBLESHOOTING DNS"
echo " $TS"
echo " Modo: $([ "$DEEP" -eq 1 ] && echo PROFUNDO || echo NORMAL)"
[ -n "$DOMAIN" ] && echo " Domínio direcionado: $DOMAIN"
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
I_UDP="$(dig @"$DNS" dnssec-failed.org A +dnssec +time=3 +tries=1 2>/dev/null || true)"
if echo "$I_UDP"|grep -q 'status: SERVFAIL'; then
    ok "DNSSEC inválido recusado com SERVFAIL via UDP."
else
    info "Teste DNSSEC inválido via UDP não retornou SERVFAIL; tentando TCP."
    I_TCP="$(dig @"$DNS" dnssec-failed.org A +dnssec +tcp +time=5 +tries=1 2>/dev/null || true)"
    if echo "$I_TCP"|grep -q 'status: SERVFAIL'; then
        ok "DNSSEC inválido recusado com SERVFAIL via TCP; validação DNSSEC está funcionando."
        warn "A tentativa UDP do teste DNSSEC inválido não concluiu; investigar apenas se isso se repetir."
    elif echo "$I_UDP$I_TCP"|grep -Eq 'no servers could be reached|timed out|communications error'; then
        warn "Não foi possível concluir o teste DNSSEC inválido por timeout/conectividade. Isso NÃO prova falha de validação DNSSEC."
    else
        err "DNSSEC inválido não retornou SERVFAIL nem via UDP nem via TCP."
    fi
fi

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
CPU="$(LC_ALL=C top -bn1 2>/dev/null|awk '/Cpu\(s\)/{for(i=1;i<=NF;i++) if($i ~ /id,?$/){gsub(/,/,"",$(i-1)); printf "%.1f",100-$(i-1); exit}}')"
RAM="$(awk '/MemTotal:/{t=$2}/MemAvailable:/{a=$2}END{if(t>0)printf "%.1f",((t-a)/t)*100}' /proc/meminfo)"
SWAP="$(awk '/SwapTotal:/{t=$2}/SwapFree:/{f=$2}END{if(t>0)printf "%.1f",((t-f)/t)*100;else print "0.0"}' /proc/meminfo)"
LOAD="$(awk '{print $1}' /proc/loadavg)"
echo "CPU  : ${CPU:-N/D}%"; echo "RAM  : ${RAM:-N/D}%"; echo "SWAP : ${SWAP:-N/D}%"; echo "LOAD : ${LOAD:-N/D}"
if [ -n "${RAM:-}" ] && awk "BEGIN{exit !($RAM>90)}"; then warn "Uso de RAM acima de 90%."; else ok "Memória sem saturação crítica."; fi

section "8 - REDE / UDP"
if command -v nstat >/dev/null 2>&1; then
    E1="$(get_nstat UdpInErrors)"; R1="$(get_nstat UdpRcvbufErrors)"; S1="$(get_nstat UdpSndbufErrors)"; N1="$(get_nstat UdpNoPorts)"
    dig @"$DNS" example.com A +time=2 +tries=1 >/dev/null 2>&1 || true
    sleep 1
    E2="$(get_nstat UdpInErrors)"; R2="$(get_nstat UdpRcvbufErrors)"; S2="$(get_nstat UdpSndbufErrors)"; N2="$(get_nstat UdpNoPorts)"
    echo "UdpInErrors      : ${E2:-0} (delta $(( ${E2:-0} - ${E1:-0} )))"
    echo "UdpRcvbufErrors  : ${R2:-0} (delta $(( ${R2:-0} - ${R1:-0} )))"
    echo "UdpSndbufErrors  : ${S2:-0} (delta $(( ${S2:-0} - ${S1:-0} )))"
    echo "UdpNoPorts       : ${N2:-0} (informativo; não penaliza o score)"
    DERR=$(( (${E2:-0}-${E1:-0}) + (${R2:-0}-${R1:-0}) + (${S2:-0}-${S1:-0}) ))
    if [ "$DERR" -gt 0 ]; then warn "Erros UDP críticos aumentaram durante a amostragem."; else ok "Nenhum aumento de erro UDP crítico durante a amostragem."; fi
else info "nstat não disponível."; fi

section "9 - COMPARAÇÃO DE CONECTIVIDADE"
for target in "LOCAL:$DNS" "CLOUDFLARE:1.1.1.1" "GOOGLE:8.8.8.8"; do name="${target%%:*}"; srv="${target#*:}"; if ms="$(dig_ms "$srv" example.com A)"; then echo "$name = ${ms} ms"; else echo "$name = FALHOU"; fi; done
info "DNS externos são usados SOMENTE como comparação; não são configurados como forwarders."

if [ -n "$DOMAIN" ]; then
 section "10 - TESTE DIRECIONADO: $DOMAIN"
 unbound-control flush "$DOMAIN" >/dev/null 2>&1 || true
 A1="$(dig @"$DNS" "$DOMAIN" A +dnssec +time=5 +tries=1 +stats 2>/dev/null || true)"
 S1="$(echo "$A1"|sed -n 's/.*status: \([^,]*\).*/\1/p'|head -1)"
 T1D="$(echo "$A1"|awk '/Query time:/ {print $4;exit}')"
 AN1="$(echo "$A1"|awk '/^;; ANSWER SECTION:/{f=1;next}/^$/{if(f)exit}f&&$4=="A"{c++}END{print c+0}')"
 echo "A primeira consulta : status=${S1:-N/D} tempo=${T1D:-N/D} ms respostas=$AN1"
 if [ "$S1" = "NOERROR" ]; then ok "$DOMAIN respondeu registro A."; else err "$DOMAIN falhou na consulta A: ${S1:-SEM RESPOSTA}."; fi
 A2="$(dig @"$DNS" "$DOMAIN" A +dnssec +time=5 +tries=1 +stats 2>/dev/null || true)"
 T2D="$(echo "$A2"|awk '/Query time:/ {print $4;exit}')"
 echo "A segunda consulta  : tempo=${T2D:-N/D} ms"
 if [ -n "${T1D:-}" ] && [ -n "${T2D:-}" ] && [ "$T2D" -le "$T1D" ]; then ok "Cache do domínio confirmado pela segunda consulta."; else warn "Cache do domínio não apresentou ganho de tempo claro."; fi
 AAAA="$(dig @"$DNS" "$DOMAIN" AAAA +dnssec +time=5 +tries=1 +stats 2>/dev/null || true)"
 S6="$(echo "$AAAA"|sed -n 's/.*status: \([^,]*\).*/\1/p'|head -1)"
 T6="$(echo "$AAAA"|awk '/Query time:/ {print $4;exit}')"
 echo "AAAA                : status=${S6:-N/D} tempo=${T6:-N/D} ms"
 if [ "$S6" = "NOERROR" ] || [ "$S6" = "NXDOMAIN" ]; then ok "Consulta AAAA respondeu sem timeout."; else warn "Consulta AAAA retornou ${S6:-SEM RESPOSTA}."; fi
 U="$(dig @"$DNS" "$DOMAIN" A +time=5 +tries=1 +stats 2>/dev/null || true)"; TU="$(echo "$U"|awk '/Query time:/ {print $4;exit}')"
 if echo "$U"|grep -q 'status: NOERROR'; then ok "UDP/53 respondeu (${TU:-N/D} ms)."; else err "UDP/53 falhou para $DOMAIN."; fi
 T="$(dig @"$DNS" "$DOMAIN" A +tcp +time=5 +tries=1 +stats 2>/dev/null || true)"; TT="$(echo "$T"|awk '/Query time:/ {print $4;exit}')"
 if echo "$T"|grep -q 'status: NOERROR'; then ok "TCP/53 respondeu (${TT:-N/D} ms)."; else err "TCP/53 falhou para $DOMAIN."; fi
 echo; echo "Comparação apenas para diagnóstico:"
 for target in "LOCAL:$DNS" "CLOUDFLARE:1.1.1.1" "GOOGLE:8.8.8.8"; do name="${target%%:*}"; srv="${target#*:}"; OUTD="$(dig @"$srv" "$DOMAIN" A +time=5 +tries=1 +stats 2>/dev/null || true)"; STD="$(echo "$OUTD"|sed -n 's/.*status: \([^,]*\).*/\1/p'|head -1)"; MSD="$(echo "$OUTD"|awk '/Query time:/ {print $4;exit}')"; echo "  $name -> status=${STD:-FALHOU} tempo=${MSD:-N/D} ms"; done
 if echo "$A1"|grep -Eq 'flags:.*\bad\b'; then ok "Resposta A do domínio foi autenticada com flag AD."; else info "Resposta A não apresentou flag AD (isso pode ser normal se a zona não usar DNSSEC)."; fi
 if [ "$DEEP" -eq 1 ]; then echo; echo "Trace de delegação (resumo):"; dig "$DOMAIN" A +trace +time=3 +tries=1 2>/dev/null | grep -E '^[^;].*[[:space:]](NS|A|AAAA)[[:space:]]' | tail -25 || true; fi
fi

if [ "$DEEP" -eq 1 ]; then
 section "$([ -n "$DOMAIN" ] && echo 11 || echo 10) - ROOT / TLD / TCP (PROFUNDO)"
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
echo; echo "Normal : /root/unbound-troubleshooting.sh"; echo "Profundo: /root/unbound-troubleshooting.sh --deep"; echo "Domínio: /root/unbound-troubleshooting.sh --domain instagram.com"; echo "============================================================"
