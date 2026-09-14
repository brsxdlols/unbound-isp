#!/bin/bash
set -e

# ============================================================
# UNBOUND ISP - DNS RECURSIVO SEM PAINEL
# Instalador / Atualizador seguro + named.cache + DNSSEC
# Compatível com Debian 12/13
# ============================================================

VERSION="2.2"
UNBOUND_CONF="/etc/unbound/unbound.conf"
CONF_DIR="/etc/unbound/unbound.conf.d"
DNSSEC_CONF="$CONF_DIR/root-auto-trust-anchor-file.conf"
ROOT_KEY="/var/lib/unbound/root.key"
ROOT_HINTS="/var/lib/unbound/root.hints"
ROOT_HINTS_URL="https://www.internic.net/domain/named.cache"
BACKUP_DIR="/root/unbound-backups"
MANAGED_MARKER="/etc/unbound/.unbound-isp-managed"
TROUBLESHOOTING_REF="c85e77e01a52cbaea7b7a8b6f7abba255e7691b2"

banner() {
    echo "============================================================"
    echo " UNBOUND ISP - DNS RECURSIVO SEM PAINEL v$VERSION"
    echo " named.cache + DNSSEC + troubleshooting"
    echo "============================================================"
    echo
}

if [ "$(id -u)" -ne 0 ]; then
    echo "ERRO: execute este script como root."
    exit 1
fi

banner
mkdir -p "$BACKUP_DIR"
touch /etc/modules /etc/sysctl.conf

ensure_download_tool() {
    if command -v curl >/dev/null 2>&1; then DOWNLOAD_TOOL="curl"; return; fi
    if command -v wget >/dev/null 2>&1; then DOWNLOAD_TOOL="wget"; return; fi
    echo "[INFO] curl/wget não encontrado. Instalando curl..."
    apt-get update
    apt-get install -y curl ca-certificates
    DOWNLOAD_TOOL="curl"
}

fetch_to() {
    local URL="$1" DEST="$2"
    ensure_download_tool
    if [ "$DOWNLOAD_TOOL" = "curl" ]; then
        curl -fsSL --connect-timeout 15 --max-time 60 "$URL" -o "$DEST"
    else
        wget -q --timeout=60 "$URL" -O "$DEST"
    fi
}

install_troubleshooting() {
    local URL="https://raw.githubusercontent.com/brsxdlols/unbound-isp/${TROUBLESHOOTING_REF}/troubleshooting/unbound-troubleshooting.sh"
    echo "[INFO] Instalando troubleshooting estável..."
    if ! fetch_to "$URL" /root/unbound-troubleshooting.sh; then
        echo "ERRO: não foi possível baixar o troubleshooting do projeto."
        return 1
    fi
    chmod +x /root/unbound-troubleshooting.sh
    echo "[OK] Troubleshooting instalado."
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
    local KEY="$1" VALUE="$2"
    sed -i -E "/^[[:space:]]*${KEY//./\\.}[[:space:]]*=/d" /etc/sysctl.conf
    echo "$KEY = $VALUE" >> /etc/sysctl.conf
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

download_root_hints() {
    local TMP
    TMP="$(mktemp)"
    echo
    echo "=== Atualizando named.cache / root hints ==="
    echo "Fonte: $ROOT_HINTS_URL"
    fetch_to "$ROOT_HINTS_URL" "$TMP"

    if [ ! -s "$TMP" ]; then
        rm -f "$TMP"
        echo "ERRO: named.cache baixado está vazio."
        exit 1
    fi
    if [ "$(wc -c < "$TMP")" -lt 1000 ]; then
        rm -f "$TMP"
        echo "ERRO: named.cache baixado parece incompleto."
        exit 1
    fi
    if ! grep -Eq '[[:space:]]NS[[:space:]]+[A-M]\.ROOT-SERVERS\.NET\.' "$TMP"; then
        rm -f "$TMP"
        echo "ERRO: conteúdo baixado não parece ser um named.cache válido."
        exit 1
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

backup_config() {
    if [ -s "$UNBOUND_CONF" ]; then
        local BKP="$BACKUP_DIR/unbound.conf-$(date +%Y%m%d-%H%M%S)"
        cp -a "$UNBOUND_CONF" "$BKP"
        LAST_BACKUP="$BKP"
        echo "[OK] Backup: $BKP"
    else
        LAST_BACKUP=""
    fi
}

restore_backup_if_possible() {
    if [ -n "${LAST_BACKUP:-}" ] && [ -f "$LAST_BACKUP" ]; then
        echo "[INFO] Restaurando configuração anterior..."
        cp -a "$LAST_BACKUP" "$UNBOUND_CONF"
        unbound-checkconf "$UNBOUND_CONF" >/dev/null 2>&1 && systemctl restart unbound || true
        echo "[OK] Backup restaurado: $LAST_BACKUP"
    fi
}

is_managed_install() {
    [ -f "$MANAGED_MARKER" ] && return 0
    [ -s "$UNBOUND_CONF" ] && grep -qE 'Unbound - Gerado automaticamente|UNBOUND ISP - GERENCIADO' "$UNBOUND_CONF" && return 0
    return 1
}

ensure_dnssec_root_key() {
    mkdir -p "$CONF_DIR" /var/lib/unbound

    if [ ! -s "$ROOT_KEY" ]; then
        if [ -s /usr/share/dns/root.key ]; then
            install -o unbound -g unbound -m 0644 /usr/share/dns/root.key "$ROOT_KEY"
            echo "[OK] root.key inicial criado a partir do pacote Debian."
        else
            echo "ERRO: root.key não existe e /usr/share/dns/root.key não está disponível."
            return 1
        fi
    else
        chown unbound:unbound "$ROOT_KEY"
        chmod 0644 "$ROOT_KEY"
        echo "[OK] root.key presente."
    fi

    if [ ! -s "$DNSSEC_CONF" ] || ! grep -Eq '^[[:space:]]*auto-trust-anchor-file:[[:space:]]*"/var/lib/unbound/root\.key"' "$DNSSEC_CONF"; then
        cat > "$DNSSEC_CONF" <<'EOF'
server:
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
EOF
        chown root:root "$DNSSEC_CONF"
        chmod 0644 "$DNSSEC_CONF"
        echo "[OK] Configuração do trust anchor criada: $DNSSEC_CONF"
        DNSSEC_CONFIG_CHANGED="yes"
    else
        echo "[OK] Trust anchor já configurado em $DNSSEC_CONF"
    fi
}

ensure_conf_d_include() {
    INCLUDE_CONFIG_CHANGED="no"

    if grep -Eq '^[[:space:]]*(include|include-toplevel):[[:space:]]*"?/etc/unbound/unbound\.conf\.d/\*\.conf"?' "$UNBOUND_CONF"; then
        echo "[OK] Diretório unbound.conf.d já incluído na configuração principal."
        return 0
    fi

    echo >> "$UNBOUND_CONF"
    echo '# Configuracoes adicionais Debian / Unbound ISP' >> "$UNBOUND_CONF"
    echo 'include: "/etc/unbound/unbound.conf.d/*.conf"' >> "$UNBOUND_CONF"
    INCLUDE_CONFIG_CHANGED="yes"
    echo "[OK] Include do Debian/Unbound ISP adicionado ao unbound.conf."
}

ensure_root_hints_directive() {
    ROOT_HINTS_CONFIG_CHANGED="no"
    if grep -Eq '^[[:space:]]*root-hints:[[:space:]]*"/var/lib/unbound/root\.hints"' "$UNBOUND_CONF"; then
        echo "[OK] root-hints já configurado no Unbound."
        return
    fi

    echo "[INFO] Adicionando root-hints ao bloco server..."
    sed -i '/^[[:space:]]*server:[[:space:]]*$/a\    root-hints: "/var/lib/unbound/root.hints"' "$UNBOUND_CONF"
    if ! grep -Eq '^[[:space:]]*root-hints:[[:space:]]*"/var/lib/unbound/root\.hints"' "$UNBOUND_CONF"; then
        echo "ERRO: não foi possível inserir root-hints."
        return 1
    fi
    ROOT_HINTS_CONFIG_CHANGED="yes"
    echo "[OK] root-hints incluído."
}

validate_and_restart() {
    echo
    echo "=== Validação da configuração ==="
    if ! unbound-checkconf "$UNBOUND_CONF"; then
        echo "ERRO: configuração inválida."
        restore_backup_if_possible
        return 1
    fi

    systemctl enable unbound >/dev/null 2>&1 || true
    if ! systemctl restart unbound; then
        echo "ERRO: falha ao reiniciar o Unbound."
        restore_backup_if_possible
        return 1
    fi
    sleep 3

    if ! systemctl is-active --quiet unbound; then
        echo "ERRO: serviço Unbound não está ativo."
        restore_backup_if_possible
        return 1
    fi
    echo "[OK] Unbound ativo."
}

validate_dnssec() {
    echo
    echo "=== Validação obrigatória do DNSSEC ==="

    local TRUST VALID BAD BAD_TCP
    TRUST="$(unbound-control get_option auto-trust-anchor-file 2>/dev/null || true)"
    if ! printf '%s' "$TRUST" | grep -q '/var/lib/unbound/root.key'; then
        echo "[ERRO] Trust anchor não está ativo no Unbound."
        echo "       Retorno: ${TRUST:-<vazio>}"
        return 1
    fi
    echo "[OK] Trust anchor ativo: /var/lib/unbound/root.key"

    unbound-control flush_zone . >/dev/null 2>&1 || true

    VALID="$(dig @127.0.0.1 cloudflare.com A +dnssec +time=5 +tries=1 2>/dev/null || true)"
    if printf '%s\n' "$VALID" | grep -q 'status: NOERROR' && \
       printf '%s\n' "$VALID" | grep -Eq 'flags:.*[[:space:]]ad([[:space:];]|$)'; then
        echo "[OK] DNSSEC válido: cloudflare.com = NOERROR + AD."
    else
        echo "[ERRO] Zona DNSSEC válida não retornou NOERROR + AD."
        return 1
    fi

    BAD="$(dig @127.0.0.1 dnssec-failed.org A +dnssec +time=5 +tries=1 2>/dev/null || true)"
    if printf '%s\n' "$BAD" | grep -q 'status: SERVFAIL'; then
        echo "[OK] DNSSEC inválido: dnssec-failed.org = SERVFAIL via UDP."
        return 0
    fi

    echo "[INFO] UDP não retornou SERVFAIL; confirmando via TCP..."
    BAD_TCP="$(dig @127.0.0.1 dnssec-failed.org A +dnssec +tcp +time=5 +tries=1 2>/dev/null || true)"
    if printf '%s\n' "$BAD_TCP" | grep -q 'status: SERVFAIL'; then
        echo "[OK] DNSSEC inválido: dnssec-failed.org = SERVFAIL via TCP."
        return 0
    fi

    echo "[ERRO] dnssec-failed.org não retornou SERVFAIL nem via UDP nem via TCP."
    return 1
}

existing_install_update() {
    echo "============================================================"
    echo " Unbound ISP já configurado detectado"
    echo " MODO: ATUALIZAÇÃO SEGURA"
    echo "============================================================"
    echo
    echo "O instalador NÃO irá:"
    echo " - sobrescrever parâmetros existentes de CPU/RAM/cache"
    echo " - pedir ACL IPv4/IPv6 novamente"
    echo " - reinstalar o Unbound"
    echo
    echo "Será garantido:"
    echo " - módulos/sysctl sem duplicação"
    echo " - named.cache / root.hints"
    echo " - include de /etc/unbound/unbound.conf.d/*.conf"
    echo " - root.key / trust anchor DNSSEC"
    echo " - validação NOERROR+AD e SERVFAIL"
    echo

    if ! unbound-checkconf "$UNBOUND_CONF"; then
        echo "ERRO: configuração atual do Unbound já está inválida."
        echo "Nenhuma alteração será aplicada."
        exit 1
    fi

    backup_config
    apply_kernel_tuning
    install_troubleshooting

    ROOT_HINTS_CHANGED="no"
    ROOT_HINTS_CONFIG_CHANGED="no"
    DNSSEC_CONFIG_CHANGED="no"
    INCLUDE_CONFIG_CHANGED="no"

    download_root_hints
    ensure_root_hints_directive || { restore_backup_if_possible; exit 1; }
    ensure_dnssec_root_key || { restore_backup_if_possible; exit 1; }
    ensure_conf_d_include

    chown unbound:unbound "$UNBOUND_CONF" "$ROOT_HINTS"

    validate_and_restart || exit 1

    if ! validate_dnssec; then
        echo
        echo "ERRO: atualização NÃO será considerada concluída porque o DNSSEC falhou."
        restore_backup_if_possible
        exit 1
    fi

    touch "$MANAGED_MARKER"
    printf 'version=%s\nupdated=%s\n' "$VERSION" "$(date -Iseconds)" > "$MANAGED_MARKER"

    echo
    echo "=============================================="
    echo " ATUALIZAÇÃO CONCLUÍDA COM SUCESSO"
    echo " DNSSEC: VALIDADO"
    echo " named.cache: $ROOT_HINTS"
    echo " unbound.conf: preservado + garantias aplicadas"
    echo "=============================================="
    echo

    read -p "Deseja executar o troubleshooting completo agora? (S/n): " RUN_TS
    RUN_TS="${RUN_TS:-S}"
    if [[ "$RUN_TS" =~ ^[Ss]$ ]]; then /root/unbound-troubleshooting.sh; fi
    exit 0
}

# -----------------------------------------------------------------
# Detecção segura: pacote instalado NÃO significa instalação nossa.
# -----------------------------------------------------------------
if command -v unbound >/dev/null 2>&1 || [ -e "$UNBOUND_CONF" ] || [ -d /etc/unbound ]; then
    echo "============================================================"
    echo " UNBOUND EXISTENTE DETECTADO"
    echo "============================================================"
    echo
    echo "1 - Atualizar / reparar preservando a configuração atual"
    echo "2 - REINSTALAR DO ZERO (limpa Unbound e configura novamente)"
    echo "3 - Cancelar"
    echo
    read -p "Escolha [1]: " EXISTING_ACTION
    EXISTING_ACTION="${EXISTING_ACTION:-1}"

    case "$EXISTING_ACTION" in
        1)
            if is_managed_install && command -v unbound-checkconf >/dev/null 2>&1 && [ -s "$UNBOUND_CONF" ]; then
                existing_install_update
            fi
            echo
            echo "[INFO] Esta instalação antiga não foi identificada como gerenciada pelo Unbound ISP."
            echo "[INFO] Para evitar alterar uma configuração desconhecida, escolha a reinstalação do zero."
            exit 0
            ;;
        2)
            echo
            echo "ATENÇÃO: a reinstalação do zero removerá:"
            echo " - pacote e configuração atual do Unbound"
            echo " - /etc/unbound"
            echo " - /var/lib/unbound"
            echo " - marcador/configuração antiga do Unbound ISP"
            echo
            echo "Um backup de /etc/unbound e /var/lib/unbound será salvo em $BACKUP_DIR."
            read -p "Confirma APAGAR o Unbound atual e reinstalar do zero? Digite REINSTALAR: " CONFIRM_REINSTALL
            if [ "$CONFIRM_REINSTALL" != "REINSTALAR" ]; then
                echo "Reinstalação cancelada."
                exit 0
            fi

            mkdir -p "$BACKUP_DIR"
            REINSTALL_BKP="$BACKUP_DIR/reinstalacao-$(date +%Y%m%d-%H%M%S)"
            mkdir -p "$REINSTALL_BKP"
            [ -d /etc/unbound ] && cp -a /etc/unbound "$REINSTALL_BKP/" || true
            [ -d /var/lib/unbound ] && cp -a /var/lib/unbound "$REINSTALL_BKP/" || true
            echo "[OK] Backup salvo em: $REINSTALL_BKP"

            systemctl stop unbound 2>/dev/null || true
            apt-get purge -y unbound unbound-anchor 2>/dev/null || apt-get purge -y unbound || true
            apt-get autoremove -y || true

            rm -rf /etc/unbound
            rm -rf /var/lib/unbound
            rm -f "$MANAGED_MARKER"
            rm -f /var/log/unbound.log

            echo "[OK] Instalação antiga removida."
            echo "[INFO] Iniciando instalação limpa do Unbound ISP..."
            ;;
        3)
            echo "Instalação cancelada."
            exit 0
            ;;
        *)
            echo "Opção inválida."
            exit 1
            ;;
    esac
fi

echo "Executando instalação completa..."
echo

apply_kernel_tuning

apt-get update
apt-get install -y unbound dnstop dnsutils curl ca-certificates

install_troubleshooting

echo
echo "=== Parâmetros da VM ==="
read -p "Quantos núcleos de CPU a VM possui? " CPU
read -p "Quantos GB de RAM a VM possui? " RAM_GB

if ! [[ "$CPU" =~ ^[0-9]+$ ]] || [ "$CPU" -lt 1 ]; then
    echo "ERRO: quantidade de CPU inválida."
    exit 1
fi
if ! [[ "$RAM_GB" =~ ^[0-9]+$ ]] || [ "$RAM_GB" -lt 1 ]; then
    echo "ERRO: quantidade de RAM inválida."
    exit 1
fi

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
        else
            echo " - Nenhuma rede IPv6 adicional informada"
        fi
        echo "=============================================="
        read -p "As redes IPv6 acima estão corretas? (s/n): " IPV6_OK
        if [[ "$IPV6_OK" =~ ^[Ss]$ ]]; then break; fi
        echo "OK. Vamos informar as redes IPv6 novamente."
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
    else
        echo " - Nenhuma rede adicional informada"
    fi
    echo "=============================================="
    read -p "As redes IPv4 acima estão corretas? (s/n): " IPV4_OK
    if [[ "$IPV4_OK" =~ ^[Ss]$ ]]; then break; fi
    echo "OK. Vamos informar as redes IPv4 novamente."
done

MSG_CACHE=$((RAM_GB * 512))
RRSET_CACHE=$((RAM_GB * 256))
if (( CPU <= 2 )); then
    SLABS=2
elif (( CPU <= 4 )); then
    SLABS=4
elif (( CPU <= 8 )); then
    SLABS=8
else
    SLABS=16
fi

ROOT_HINTS_CHANGED="no"
download_root_hints

backup_config

echo
echo "Gerando configuração do Unbound..."
cat > "$UNBOUND_CONF" <<EOF
# ==========================================
# UNBOUND ISP - GERENCIADO
# Unbound - Gerado automaticamente
# Versao do instalador: $VERSION
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

# Configuracoes adicionais Debian / Unbound ISP
include: "/etc/unbound/unbound.conf.d/*.conf"
EOF

chown unbound:unbound "$UNBOUND_CONF" "$ROOT_HINTS"

DNSSEC_CONFIG_CHANGED="no"
INCLUDE_CONFIG_CHANGED="no"
ensure_dnssec_root_key || { restore_backup_if_possible; exit 1; }

# Obrigatório também em instalação nova: o trust anchor do Debian fica
# em /etc/unbound/unbound.conf.d e precisa estar incluído na config ativa.
ensure_conf_d_include || { restore_backup_if_possible; exit 1; }

validate_and_restart || exit 1

if ! validate_dnssec; then
    echo
    echo "============================================================"
    echo " INSTALAÇÃO NÃO CONCLUÍDA"
    echo " DNSSEC não passou na validação obrigatória."
    echo " A configuração anterior será restaurada quando houver backup."
    echo "============================================================"
    restore_backup_if_possible
    exit 1
fi

echo
echo "Configurando /etc/resolv.conf para DNS local..."
cat > /etc/resolv.conf <<'EOF'
nameserver 127.0.0.1
options timeout:1 attempts:3
EOF

touch "$MANAGED_MARKER"
printf 'version=%s\ninstalled=%s\n' "$VERSION" "$(date -Iseconds)" > "$MANAGED_MARKER"

echo
echo "=== Testes DNS (cache) ==="
echo "Primeira consulta:"
dig google.com @127.0.0.1 +time=5 +tries=1 | grep "Query time" || true
echo "Segunda consulta:"
dig google.com @127.0.0.1 +time=5 +tries=1 | grep "Query time" || true

echo
echo "=== named.cache / root hints ==="
echo "Arquivo : $ROOT_HINTS"
echo "Linhas  : $(wc -l < "$ROOT_HINTS")"
echo "Tamanho : $(wc -c < "$ROOT_HINTS") bytes"

echo
echo "=============================================="
echo " INSTALAÇÃO CONCLUÍDA COM SUCESSO"
echo " Unbound: ATIVO"
echo " DNSSEC : VALIDADO (NOERROR+AD / SERVFAIL)"
echo " IPv6   : $DO_IPV6"
echo " CPU    : $CPU"
echo " RAM    : ${RAM_GB}GB"
echo " named.cache: ATIVO"
echo " Painel : NÃO INSTALADO"
echo "=============================================="

echo
read -p "Deseja executar o troubleshooting completo agora? (S/n): " RUN_TS
RUN_TS="${RUN_TS:-S}"
if [[ "$RUN_TS" =~ ^[Ss]$ ]]; then
    /root/unbound-troubleshooting.sh
fi
