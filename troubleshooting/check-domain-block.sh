#!/usr/bin/env bash
# Unbound ISP - Verificador direcionado de bloqueio DNS
set -uo pipefail
DOMAIN="${1:-}"
if [[ ! "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ || "$DOMAIN" != *.* || ${#DOMAIN} -gt 253 ]]; then
  echo "Uso: bash <(curl -fsSL URL) dominio.com"; exit 2
fi
DOMAIN="${DOMAIN,,}"
for cmd in dig timeout; do command -v "$cmd" >/dev/null || { echo "ERRO: falta $cmd"; exit 2; }; done
echo "=================================================="
echo " VERIFICADOR DE BLOQUEIO DNS - $DOMAIN"
echo "=================================================="
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
check() {
  local label="$1" server="$2" type="$3" file="$4"
  timeout 8 dig @"$server" "$DOMAIN" "$type" +time=3 +tries=1 +noall +comments +answer > "$file" 2>&1 || true
  local status
  status="$(sed -n 's/.*status: \([A-Z]*\).*/\1/p' "$file" | head -1)"
  printf '%-18s %-5s %-9s ' "$label" "$type" "${status:-TIMEOUT}"
  awk -v t="$type" '$4==t {printf "%s ",$5}' "$file"
  echo
}
for type in A AAAA; do
  check LOCAL 127.0.0.1 "$type" "$tmp/local.$type"
  check CLOUDFLARE 1.1.1.1 "$type" "$tmp/cf.$type"
  check GOOGLE 8.8.8.8 "$type" "$tmp/google.$type"
done
status() { sed -n 's/.*status: \([A-Z]*\).*/\1/p' "$1" | head -1; }
has_answer() { awk -v t="$2" '$4==t {found=1} END {exit !found}' "$1"; }
local_good=0; external_good=0; local_bad=0
for type in A AAAA; do
  ls="$(status "$tmp/local.$type")"
  if [[ "$ls" == NOERROR ]] && has_answer "$tmp/local.$type" "$type"; then
    local_good=1
  fi
  if [[ "$ls" == NXDOMAIN || "$ls" == REFUSED || "$ls" == SERVFAIL ]]; then local_bad=1; fi
  for provider in cf google; do
    if [[ "$(status "$tmp/$provider.$type")" == NOERROR ]] && has_answer "$tmp/$provider.$type" "$type"; then
      external_good=1
    fi
  done
done
echo
if ((local_good)); then
  echo "RESULTADO: NAO HA BLOQUEIO DNS EVIDENTE (dominio resolve localmente)."
  echo "OBS: isso nao comprova acesso ao site nem exclui filtragem de IP."
elif ((local_bad && external_good)); then
  echo "RESULTADO: SUSPEITA DE BLOQUEIO OU FALHA NO DNS LOCAL."
  echo "O dominio resolve externamente, mas falha localmente."
  echo "NXDOMAIN, REFUSED ou SERVFAIL tambem podem ter outras causas."
else
  echo "RESULTADO: INCONCLUSIVO."
  echo "Verifique conectividade, registros e politicas DNS."
fi
echo
echo "OBS: respostas diferentes de IP entre provedores podem ser normais (CDN)."
