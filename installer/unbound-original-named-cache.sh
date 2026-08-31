#!/bin/bash
set -e

# ============================================================
# UNBOUND - INSTALADOR ORIGINAL + NAMED.CACHE / ROOT.HINTS
# Reexecução segura e idempotente
# ============================================================

UNBOUND_CONF="/etc/unbound/unbound.conf"
ROOT_HINTS="/var/lib/unbound/root.hints"
ROOT_HINTS_URL="https://www.internic.net/domain/named.cache"
BACKUP_DIR="/root/unbound-backups"

echo "============================================================"
echo " Unbound - Instalador / Atualizador"
echo " named.cache (root hints) automático"
echo "============================================================"
echo

if [ "$(id -u)" -ne 0 ]; then
    echo "ERRO: execute este script como root."
    exit 1
fi

install_troubleshooting() {
    local url="https://raw.githubusercontent.com/brsxdlols/unbound-isp/main/troubleshooting/unbound-troubleshooting.sh"
    if ! curl -fsSL "$url" -o /root/unbound-troubleshooting.sh; then
        echo "ERRO: não foi possível baixar o troubleshooting do projeto."
        return 1
    fi
    chmod +x /root/unbound-troubleshooting.sh
}

ensure_module() {
    local MOD="$1"
    modprobe -a "$MOD" 2>/dev/null || true
    if ! grep -qxF "$MOD" /etc/modules 2>/dev/null; then
        echo "$MOD" >> /etc/modules
        echo "[OK] Módulo adicionado em /etc/modules: $MOD"
    else
        echo "[OK] Módulo já presente: $MOD"
    fi
}

set_sysctl_value() {
    local KEY="$1"
    local VALUE="$2"
    sed -i -E "/^[[:space:]]*${KEY//./\\.}[[:space:]]*=/d" /etc/sysctl.conf
    echo "$KEY = $VALUE" >> /etc/sysctl.conf
}

ensure_download_tool() {
    if command -v curl >/dev/null 2>&1; then DOWNLOAD_TOOL="curl"; return; fi
    if command -v wget >/dev/null 2>&1; then DOWNLOAD_TOOL="wget"; return; fi
    echo "[INFO] curl/wget não encontrado. Instalando somente curl..."
    apt-get update
    apt-get install -y curl ca-certificates
    DOWNLOAD_TOOL="curl"
}

download_root_hints() {
    local TMP
    TMP="$(mktemp)"
    ensure_download_tool
    echo
    echo "=== Atualizando named.cache / root hints ==="
    echo "Fonte: $ROOT_HINTS_URL"
    if [ "$DOWNLOAD_TOOL" = "curl" ]; then
        curl -fsSL --connect-timeout 15 --max-time 30 "$ROOT_HINTS_URL" -o "$TMP"
    else
        wget -q --timeout=30 "$ROOT_HINTS_URL" -O "$TMP"
    fi
    if [ ! -s "$TMP" ]; then rm -f "$TMP"; echo "ERRO: named.cache baixado está vazio."; exit 1; fi
    if [ "$(wc -c < "$TMP")" -lt 1000 ]; then rm -f "$TMP"; echo "ERRO: named.cache baixado parece incompleto."; exit 1; fi
    if ! grep -Eq '[[:space:]]NS[[:space:]]+[A-M]\.ROOT-SERVERS\.NET\.' "$TMP"; then
        rm -f "$TMP"; echo "ERRO: conteúdo baixado não parece ser um named.cache válido."; exit 1
    fi
    mkdir -p /var/lib/unbound
    if [ -f "$ROOT_HINTS" ] && cmp -s "$TMP" "$ROOT_HINTS"; then
        echo "[OK] named.cache já está atualizado."
        rm -f "$TMP"
        ROOT_HINTS_CHANGED="no"
    else
        install -o unbound -g unbound -m 0644 "$TMP" "$ROOT_HINTS"
        rm -f "$TMP"
        echo "[OK] named.cache atualizado em: $ROOT_HINTS"
        ROOT_HINTS_CHANGED="yes"
    fi
}

ensure_root_hints_directive() {
    ROOT_HINTS_CONFIG_CHANGED="no"
    if grep -Eq '^[[:space:]]*root-hints:[[:space:]]*"/var/lib/unbound/root\.hints"' "$UNBOUND_CONF"; then
        echo "[OK] root-hints já configurado no Unbound."
        return
    fi
    mkdir -p "$BACKUP_DIR"
    local BKP="$BACKUP_DIR/unbound.conf-before-root-hints-$(date +%Y%m%d-%H%M%S)"
    cp -a "$UNBOUND_CONF" "$BKP"
    echo "[INFO] Adicionando root-hints ao bloco server..."
    sed -i '/^[[:space:]]*server:[[:space:]]*$/a\    root-hints: "/var/lib/unbound/root.hints"' "$UNBOUND_CONF"
    if ! grep -Eq '^[[:space:]]*root-hints:[[:space:]]*"/var/lib/unbound/root\.hints"' "$UNBOUND_CONF"; then
        cp -a "$BKP" "$UNBOUND_CONF"; echo "ERRO: não foi possível inserir root-hints."; exit 1
    fi
    if ! unbound-checkconf "$UNBOUND_CONF"; then
        echo; echo "ERRO: configuração ficou inválida. Restaurando backup..."
        cp -a "$BKP" "$UNBOUND_CONF"
        unbound-checkconf "$UNBOUND_CONF" || true
        exit 1
    fi
    ROOT_HINTS_CONFIG_CHANGED="yes"
    echo "[OK] root-hints incluído."
}

apply_kernel_tuning() {
    echo
    echo "=== Módulos TCP ==="
    ensure_module tcp_illinois
    ensure_module tcp_westwood
    ensure_module tcp_htcp
    echo
    echo "=== Ajustes de kernel e rede ==="
    set_sysctl_value vm.swappiness 5
    set_sysctl_value vm.dirty_ratio 10
    set_sysctl_value vm.dirty_background_ratio 5
    set_sysctl_value net.core.somaxconn 65535
    set_sysctl_value net.ipv4.tcp_mem "4096 87380 16777216"
    set_sysctl_value net.core.rmem_max 16777216
    set_sysctl_value net.core.wmem_max 16777216
    set_sysctl_value net.ipv4.tcp_rmem "4096 87380 16777216"
    set_sysctl_value net.ipv4.tcp_wmem "4096 65536 16777216"
    set_sysctl_value net.ipv4.tcp_sack 1
    set_sysctl_value net.ipv4.tcp_window_scaling 1
    set_sysctl_value net.ipv4.tcp_moderate_rcvbuf 1
    set_sysctl_value net.ipv4.tcp_timestamps 1
    set_sysctl_value net.ipv4.tcp_fin_timeout 15
    set_sysctl_value net.core.netdev_max_backlog 8192
    set_sysctl_value net.ipv4.ip_local_port_range "1024 65535"
    set_sysctl_value net.core.default_qdisc fq
    set_sysctl_value net.ipv4.tcp_congestion_control bbr
    set_sysctl_value net.core.rmem_max 4194304
    set_sysctl_value net.core.wmem_max 4194304
    set_sysctl_value net.core.rmem_default 4194304
    set_sysctl_value net.core.wmem_default 4194304
    sysctl -p
    echo "[OK] Sysctl aplicado sem duplicar chaves."
}

existing_install_update() {
    install_troubleshooting
    echo "============================================================"
    echo " Unbound já instalado detectado"
    echo " MODO: ATUALIZAÇÃO SEGURA"
    echo "============================================================"
    echo
    echo "O instalador NÃO irá:"
    echo " - sobrescrever sua configuração atual"
    echo " - pedir CPU/RAM novamente"
    echo " - pedir ACL IPv4/IPv6 novamente"
    echo " - reinstalar o Unbound"
    echo " - duplicar módulos/sysctl"
    echo
    echo "Será atualizado:"
    echo " - módulos/sysctl, mantendo uma única entrada"
    echo " - named.cache / root.hints"
    echo " - diretiva root-hints, somente se estiver faltando"
    echo
    if ! unbound-checkconf "$UNBOUND_CONF"; then
        echo; echo "ERRO: configuração atual do Unbound já está inválida."
        echo "Nada será alterado no unbound.conf."
        exit 1
    fi
    apply_kernel_tuning
    ROOT_HINTS_CHANGED="no"
    ROOT_HINTS_CONFIG_CHANGED="no"
    download_root_hints
    ensure_root_hints_directive
    chown unbound:unbound "$UNBOUND_CONF"
    chown unbound:unbound "$ROOT_HINTS"
    echo
    echo "=== Validação final ==="
    unbound-checkconf "$UNBOUND_CONF"
    if [ "$ROOT_HINTS_CHANGED" = "yes" ] || [ "$ROOT_HINTS_CONFIG_CHANGED" = "yes" ]; then
        echo "[INFO] Aplicando atualização no Unbound..."
        systemctl restart unbound
    else
        echo "[OK] Nenhuma alteração de Unbound necessária."
    fi
    if ! systemctl is-active --quiet unbound; then echo "ERRO: serviço Unbound não está ativo."; exit 1; fi
    echo
    echo "=== Teste DNS ==="
    dig google.com @127.0.0.1 +time=3 +tries=1 | grep -E "status:|Query time" || true
    echo
    echo "=============================================="
    echo " ATUALIZAÇÃO CONCLUÍDA"
    echo " named.cache: $ROOT_HINTS"
    echo " unbound.conf preservado"
    echo " =============================================="
    echo
    read -p "Deseja executar o troubleshooting completo agora? (S/n): " RUN_TS
    RUN_TS="${RUN_TS:-S}"
    if [[ "$RUN_TS" =~ ^[Ss]$ ]]; then /root/unbound-troubleshooting.sh; fi
    exit 0
}

if command -v unbound >/dev/null 2>&1 && command -v unbound-checkconf >/dev/null 2>&1 && [ -s "$UNBOUND_CONF" ]; then
    existing_install_update
fi

echo "Nenhuma instalação existente do Unbound foi detectada."
echo "Executando instalação completa..."
echo

touch /etc/modules
touch /etc/sysctl.conf
apply_kernel_tuning

apt update
apt install unbound dnstop dnsutils -y

echo
 echo "=== Parâmetros da VM ==="
read -p "Quantos núcleos de CPU a VM possui? " CPU
read -p "Quantos GB de RAM a VM possui? " RAM_GB

echo
read -p "Deseja habilitar IPv6 no Unbound? (s/n): " USE_IPV6
if [[ "$USE_IPV6" =~ ^[Ss]$ ]]; then
    DO_IPV6="yes"
    IPV6_INTERFACE="    interface: ::1"
    while true; do
        IPV6_BLOCKS=""
        echo
        echo "Digite os blocos IPv6 permitidos (ENTER vazio para finalizar):"
        while true; do
            read -p "Bloco IPv6 (ex: 2804:abcd::/32): " IP6
            [[ -z "$IP6" ]] && break
            IPV6_BLOCKS+="    access-control: $IP6 allow"$'\n'
        done
        echo
        echo "=============================================="
        echo " Redes IPv6 informadas"
        echo "=============================================="
        if [ -n "$IPV6_BLOCKS" ]; then
            printf "%s" "$IPV6_BLOCKS" | sed 's/^[[:space:]]*access-control:[[:space:]]*/ - /; s/[[:space:]]allow$//'
        else echo " - Nenhuma rede IPv6 adicional informada"; fi
        echo "=============================================="
        read -p "As redes IPv6 acima estão corretas? (s/n): " IPV6_OK
        if [[ "$IPV6_OK" =~ ^[Ss]$ ]]; then break; fi
        echo; echo "OK. Vamos informar as redes IPv6 novamente."
    done
else
    DO_IPV6="no"
    IPV6_INTERFACE=""
    IPV6_BLOCKS=""
fi

while true; do
    ALLOW_IPS=""
    echo
    echo "=== Redes IPv4 permitidas ==="
    echo
    echo "1 - Informar redes/blocos manualmente"
    echo "2 - Liberar consultas IPv4 para QUALQUER origem (0.0.0.0/0)"
    echo
    read -p "Escolha [1]: " IPV4_MODE
    IPV4_MODE="${IPV4_MODE:-1}"
    if [ "$IPV4_MODE" = "2" ]; then
        echo
        echo "ATENÇÃO:"
        echo "0.0.0.0/0 transforma este DNS em resolvedor aberto para qualquer IPv4."
        echo "Isso pode permitir uso indevido/abuso se a porta 53 estiver acessível pela Internet."
        echo
        read -p "Confirma liberar 0.0.0.0/0? (s/n): " OPEN_CONFIRM
        if [[ "$OPEN_CONFIRM" =~ ^[Ss]$ ]]; then
            ALLOW_IPS='    access-control: 0.0.0.0/0 allow'$'\n'
        else
            echo "Liberação total cancelada. Voltando para inclusão manual."
            IPV4_MODE="1"
        fi
    fi
    if [ "$IPV4_MODE" = "1" ]; then
        echo
        echo "Digite os blocos IPv4 permitidos (ENTER vazio para finalizar):"
        while true; do
            read -p "Bloco IPv4 (ex: 170.231.96.0/22): " IP
            [[ -z "$IP" ]] && break
            ALLOW_IPS+="    access-control: $IP allow"$'\n'
        done
    fi
    echo
    echo "=============================================="
    echo " Redes IPv4 informadas"
    echo "=============================================="
    if [ -n "$ALLOW_IPS" ]; then
        printf "%s" "$ALLOW_IPS" | sed 's/^[[:space:]]*access-control:[[:space:]]*/ - /; s/[[:space:]]allow$//'
    else echo " - Nenhuma rede adicional informada"; fi
    echo "=============================================="
    read -p "As redes IPv4 acima estão corretas? (s/n): " IPV4_OK
    if [[ "$IPV4_OK" =~ ^[Ss]$ ]]; then break; fi
    echo; echo "OK. Vamos informar as redes IPv4 novamente."
done

MSG_CACHE=$((RAM_GB * 512))
RRSET_CACHE=$((RAM_GB * 256))
if (( CPU <= 2 )); then SLABS=2
elif (( CPU <= 4 )); then SLABS=4
elif (( CPU <= 8 )); then SLABS=8
else SLABS=16
fi

ROOT_HINTS_CHANGED="no"
download_root_hints

echo
 echo "Gerando configuração do Unbound..."
cat << EOF > "$UNBOUND_CONF"
# ==========================================
# Unbound - Gerado automaticamente
# ==========================================

server:
    root-hints: "/var/lib/unbound/root.hints"

    logfile: "/var/log/unbound.log"
    use-syslog: yes
    verbosity: 1

    interface: 0.0.0.0
    interface: 127.0.0.1
$IPV6_INTERFACE
    interface-automatic: yes

    access-control: 127.0.0.0/8 allow
$ALLOW_IPS
$IPV6_BLOCKS
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 192.168.0.0/16 allow
    access-control: 100.64.0.0/10 allow
    access-control: 198.18.0.0/15 allow

    do-ip4: yes
    do-ip6: $DO_IPV6
    do-udp: yes
    do-tcp: yes

    num-threads: $CPU
    outgoing-range: 4096
    so-rcvbuf: 4m
    so-sndbuf: 4m

    msg-cache-size: ${MSG_CACHE}m
    msg-cache-slabs: $SLABS
    rrset-cache-size: ${RRSET_CACHE}m
    rrset-cache-slabs: $SLABS
    infra-cache-slabs: $SLABS
    key-cache-slabs: $SLABS

    num-queries-per-thread: 4096
    cache-max-ttl: 7200
    minimal-responses: yes
    rrset-roundrobin: yes

    statistics-interval: 0
    extended-statistics: yes
    statistics-cumulative: no

remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-port: 8953
    control-use-cert: "no"

auth-zone:
    name: "."
    master: "b.root-servers.net"
    master: "c.root-servers.net"
    master: "d.root-servers.net"
    master: "f.root-servers.net"
    master: "g.root-servers.net"
    master: "k.root-servers.net"
    master: "lax.xfr.dns.icann.org"
    master: "iad.xfr.dns.icann.org"
    fallback-enabled: yes
    for-downstream: no
    for-upstream: yes
    zonefile: "/var/lib/unbound/root.zone"
EOF

chown unbound:unbound "$UNBOUND_CONF"
chown unbound:unbound "$ROOT_HINTS"

echo
 echo "Testando configuração do Unbound..."
if ! unbound-checkconf "$UNBOUND_CONF"; then echo; echo "ERRO: configuração inválida."; exit 1; fi
systemctl enable unbound
systemctl restart unbound

echo
 echo "Configurando /etc/resolv.conf para DNS local..."
cat << EOF > /etc/resolv.conf
nameserver 127.0.0.1
options timeout:1 attempts:3
EOF

install_troubleshooting

echo
 echo "=== Testes DNS (cache) ==="
echo "Primeira consulta (sem cache):"
dig google.com @127.0.0.1 | grep "Query time" || true
echo "Segunda consulta (com cache):"
dig google.com @127.0.0.1 | grep "Query time" || true

echo
 echo "=== named.cache / root hints ==="
echo "Arquivo: $ROOT_HINTS"
echo "Linhas: $(wc -l < "$ROOT_HINTS")"
echo "Tamanho: $(wc -c < "$ROOT_HINTS") bytes"

echo
 echo "=============================================="
echo " Unbound instalado e funcionando"
echo " IPv6 habilitado: $DO_IPV6"
echo " CPU: $CPU | RAM: ${RAM_GB}GB"
echo " named.cache: ATIVO"
echo "=============================================="

echo
read -p "Deseja executar o troubleshooting completo agora? (S/n): " RUN_TS
RUN_TS="${RUN_TS:-S}"
if [[ "$RUN_TS" =~ ^[Ss]$ ]]; then /root/unbound-troubleshooting.sh; fi
