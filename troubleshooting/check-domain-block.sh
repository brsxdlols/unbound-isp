#!/usr/bin/env bash
# Unbound ISP - Verificador de bloqueio DNS / ANABLOCK v2
set -uo pipefail
DOMAIN="${1:-}"
if [[ -z "$DOMAIN" ]]; then
  if [[ ! -t 0 ]]; then
    echo "ERRO: informe um dominio como argumento (modo nao interativo)."
    exit 2
  fi
  read -r -p "Qual dominio deseja consultar? " DOMAIN
fi
check_domain() {
if [[ ! "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ || "$DOMAIN" != *.* || ${#DOMAIN} -gt 253 || "$DOMAIN" == *..* ]]; then
  echo "Uso: bash <(curl -fsSL URL) dominio.com"; exit 2
fi
DOMAIN="${DOMAIN,,}"
for cmd in dig awk grep; do command -v "$cmd" >/dev/null || { echo "ERRO: falta $cmd"; exit 2; }; done
if [[ -t 1 && "${NO_COLOR:-}" == "" ]]; then
  RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; YELLOW=$'\033[1;33m'; RESET=$'\033[0m'
else RED=""; GREEN=""; YELLOW=""; RESET=""; fi
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
echo "============================================================"
echo " VERIFICADOR DE BLOQUEIO DNS / ANABLOCK - $DOMAIN"
echo "============================================================"
query() {
  local label="$1" server="$2" typ="$3" file="$4" st
  dig @"$server" "$DOMAIN" "$typ" +time=3 +tries=1 +noall +comments +answer >"$file" 2>&1 || true
  st="$(sed -n 's/.*status: \([A-Z]*\).*/\1/p' "$file" | head -1)"
  printf '%-12s %-5s %-9s ' "$label" "$typ" "${st:-TIMEOUT}"
  awk -v t="$typ" '$4==t {printf "%s ",$5}' "$file"
  echo
}
for typ in A AAAA; do
  query LOCAL 127.0.0.1 "$typ" "$TMP/local.$typ"
  query CLOUDFLARE 1.1.1.1 "$typ" "$TMP/cf.$typ"
  query GOOGLE 8.8.8.8 "$typ" "$TMP/google.$typ"
done
status() { sed -n 's/.*status: \([A-Z]*\).*/\1/p' "$1" | head -1; }
ips() { awk -v t="$2" '$4==t {print tolower($5)}' "$1" | sort -u; }
has_answer() { [[ -n "$(ips "$1" "$2")" ]]; }
echo
# Regras ANABLOCK: apenas linhas ativas, incluindo local-zone e local-data.
# Verifica dominio exato ou subdominio de zona declarada; nao interpreta comentarios.
ANAFILE="/etc/unbound/anablock.conf"
RULES="$TMP/rules"
: >"$RULES"
if [[ -r "$ANAFILE" ]]; then
  awk -v d="$DOMAIN" '
  {
    line=$0; sub(/[[:space:]]*#.*/, "", line)
    if (line ~ /^[[:space:]]*#/) next
    if (match(line, /local-zone:[[:space:]]*"[^"]+"/)) {
      z=substr(line,RSTART,RLENGTH); sub(/^.*"/,"",z); sub(/".*$/,"",z)
    }
    if (line ~ /local-zone:[[:space:]]*"/) {
      z=line; sub(/^.*local-zone:[[:space:]]*"/,"",z); sub(/".*$/,"",z)
      z=tolower(z); sub(/\.$/,"",z)
      if (d==z || (length(d)>length(z) && substr(d,length(d)-length(z))=="."z))
        print "ZONA " line
    }
    if (line ~ /local-data:[[:space:]]*"/) {
      v=line; sub(/^.*local-data:[[:space:]]*"/,"",v); sub(/".*$/,"",v)
      split(v,a,/[[:space:]]+/); z=tolower(a[1]); sub(/\.$/,"",z)
      if (z==d) print "DADO " line
    }
  }' "$ANAFILE" >"$RULES"
fi
local_ok=0; external_ok=0; local_fail=0; different=0
for typ in A AAAA; do
  ls="$(status "$TMP/local.$typ")"
  if [[ "$ls" == NOERROR ]] && has_answer "$TMP/local.$typ" "$typ"; then local_ok=1; fi
  if [[ "$ls" == NXDOMAIN || "$ls" == REFUSED || "$ls" == SERVFAIL ]]; then local_fail=1; fi
  for p in cf google; do
    if [[ "$(status "$TMP/$p.$typ")" == NOERROR ]] && has_answer "$TMP/$p.$typ" "$typ"; then
      external_ok=1
      if has_answer "$TMP/local.$typ" "$typ" && ! diff -q <(ips "$TMP/local.$typ" "$typ") <(ips "$TMP/$p.$typ" "$typ") >/dev/null; then different=1; fi
    fi
  done
done
echo "============================================================"
if [[ -s "$RULES" ]]; then
  echo -e "${RED}████████████████████████████████████████████████████████"
  echo "  BLOQUEADO PELA ANABLOCK - REGRA LOCAL ENCONTRADA"
  echo -e "████████████████████████████████████████████████████████${RESET}"
  echo "Arquivo: $ANAFILE"
  head -n 8 "$RULES"
  echo "OBS: a regra foi encontrada no arquivo; confirme que esta incluido na configuracao ativa."
elif ((local_fail && external_ok)); then
  echo -e "${YELLOW}SUSPEITA DE BLOQUEIO OU FALHA LOCAL${RESET}"
  echo "O DNS local falhou e pelo menos um DNS externo respondeu."
elif ((local_ok)); then
  echo -e "${GREEN}████████████████████████████████████████████████████████"
  echo "  NAO BLOQUEADO PELO DNS LOCAL (SEM INDICIOS)"
  echo -e "████████████████████████████████████████████████████████${RESET}"
  if ((different)); then
    echo "INFO: IPs diferentes dos DNS publicos podem ser normais por CDN/geolocalizacao."
  fi
else
  echo -e "${YELLOW}INCONCLUSIVO - VERIFICAR DNS E CONECTIVIDADE${RESET}"
fi
echo "============================================================"
echo "OBS: verifica DNS local; nao identifica bloqueio por firewall, IP ou HTTP."

}

while true; do
  check_domain
  if [[ ! -t 0 ]]; then break; fi
  echo
  read -r -p "Deseja consultar outro dominio? [s/N]: " AGAIN || break
  case "${AGAIN,,}" in
    s|sim) read -r -p "Qual dominio deseja consultar? " DOMAIN || break ;;
    *) echo "Consulta encerrada."; break ;;
  esac
done
