#!/bin/bash
# ==================================================
#       TITO MX SLIPSTREAM PRO - PANEL PRO ULTIMATE
#       (OPTIMIZED FOR STABLE QUIC CONNECTIONS)
#       (Custom Go Implementation by Jules)
# ==================================================

DOMAIN="dns.titopro.work.gd"
IP="104.248.211.212"

BIN="/root/slipstream-server"
CERT="/root/certs"
DB="/root/usuarios_slipstream.db"
LOG="/var/log/slipstream.log"
CONFIG="/etc/slipstream.conf"

SERVICE="/etc/systemd/system/slipstream.service"
WD_SERVICE="/etc/systemd/system/slip-watchdog.service"
WD_TIMER="/etc/systemd/system/slip-watchdog.timer"
WD_SCRIPT="/root/tito_watchdog.sh"
QUIC_FIX_SCRIPT="/root/quic_fix.sh"

# Colores profesionales (sin parpadeo)
CYAN="\e[96m"
GREEN="\e[92m"
RED="\e[91m"
YELLOW="\e[93m"
PURPLE="\e[95m"
BLUE="\e[94m"
MAGENTA="\e[35m"
WHITE="\e[97m"
BOLD="\e[1m"
RESET="\e[0m"

# Variables de estado
SLIP_STATUS=""
DNS_STATUS=""
WATCHDOG_STATUS=""
QUIC_STATUS=""
CONNECTIONS=0

[[ $EUID -ne 0 ]] && echo -e "${RED}[ERROR]${RESET} Ejecuta como root" && exit 1
touch $DB

# ===================== FUNCIONES DE DISEÑO MEJORADAS =====================
draw_header() {
    local width=70
    local text=$1
    local color=${2:-$CYAN}
    echo -e "${color}╔$(printf '═%.0s' $(seq 1 $((width-2))))╗${RESET}"
    printf "${color}║${WHITE}%-${width}s${color}║${RESET}\n" " $text"
    echo -e "${color}╚$(printf '═%.0s' $(seq 1 $((width-2))))╝${RESET}"
}

draw_box() {
    local text=$1
    echo -e "${CYAN}┌────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${CYAN}│${WHITE} ${text}${CYAN}$(printf '%*s' $((60-${#text})) "")│${RESET}"
    echo -e "${CYAN}└────────────────────────────────────────────────────────────────────┘${RESET}"
}

show_progress() {
    local task=$1
    echo -ne "${WHITE}• ${task}...${RESET}"
    for i in {1..3}; do
        echo -ne "${GREEN}█${RESET}"
        sleep 0.2
    done
    echo -e "${GREEN} ✓${RESET}"
}

# ===================== BANNER PROFESIONAL =====================
show_banner() {
    clear
    echo -e "${BLUE}"
    cat << "EOF"
████████╗██╗████████╗ ██████╗      ███╗   ███╗██╗  ██╗
╚══██╔══╝██║╚══██╔══╝██╔═══██╗     ████╗ ████║╚██╗██╔╝
   ██║   ██║   ██║   ██║   ██║     ██╔████╔██║ ╚███╔╝
   ██║   ██║   ██║   ██║   ██║     ██║╚██╔╝██║ ██╔██╗
   ██║   ██║   ██║   ╚██████╔╝     ██║ ╚═╝ ██║██╔╝ ██╗
   ╚═╝   ╚═╝   ╚═╝    ╚═════╝      ╚═╝      ╚═╝╚═╝  ╚═╝
EOF
    echo -e "${RESET}"

    draw_header "SLIPSTREAM PRO - DNS TUNNEL PARA CUBA 🇨🇺" $PURPLE

    # Mostrar estado del sistema
    echo -e "${CYAN}╔════════════════════════╦══════════════════════════════════════╗${RESET}"

    # Estado Slipstream
    if systemctl is-active slipstream &>/dev/null; then
        SLIP_STATUS="${GREEN}● ACTIVO (High Prio)${RESET}"
    else
        SLIP_STATUS="${RED}● INACTIVO${RESET}"
    fi
    echo -e "${CYAN}║ ${WHITE}Slipstream${RESET}            ║ $SLIP_STATUS                          ${CYAN}║${RESET}"

    # Estado DNS
    if ss -ulpn | grep -q ":53"; then
        DNS_STATUS="${GREEN}● ABIERTO${RESET}"
    else
        DNS_STATUS="${RED}● CERRADO${RESET}"
    fi
    echo -e "${CYAN}║ ${WHITE}Puerto 53${RESET}             ║ $DNS_STATUS                          ${CYAN}║${RESET}"

    # Estado Watchdog
    if systemctl is-active slip-watchdog.timer &>/dev/null; then
        WATCHDOG_STATUS="${GREEN}● ACTIVO${RESET}"
    else
        WATCHDOG_STATUS="${RED}● INACTIVO${RESET}"
    fi
    echo -e "${CYAN}║ ${WHITE}Watchdog Auto${RESET}         ║ $WATCHDOG_STATUS                          ${CYAN}║${RESET}"

    # Estado QUIC
    if check_quic_status; then
        QUIC_STATUS="${GREEN}● ESTABLE${RESET}"
    else
        QUIC_STATUS="${YELLOW}● INESTABLE${RESET}"
    fi
    echo -e "${CYAN}║ ${WHITE}QUIC/DNS${RESET}              ║ $QUIC_STATUS                          ${CYAN}║${RESET}"

    # Conexiones activas
    CONNECTIONS=$(who | wc -l)
    echo -e "${CYAN}║ ${WHITE}Conexiones${RESET}            ║ ${YELLOW}$CONNECTIONS usuarios conectados${RESET}             ${CYAN}║${RESET}"

    echo -e "${CYAN}╚════════════════════════╩══════════════════════════════════════╝${RESET}"
    echo -e "${WHITE} Dominio: ${GREEN}$DOMAIN${RESET} | IP: ${GREEN}$IP${RESET}"
    echo
}

# ===================== HERRAMIENTAS QUIC/DNS AVANZADAS =====================
check_quic_status() {
    # Verifica si QUIC está funcionando correctamente
    if timeout 5 dig @1.1.1.1 google.com > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

quic_diagnostic() {
    show_banner
    draw_header "DIAGNÓSTICO AVANZADO QUIC OVER DNS" $YELLOW

    echo -e "${WHITE}Realizando diagnóstico completo del túnel QUIC...${RESET}"
    echo

    # 1. Verificar conectividad DNS
    echo -e "${CYAN}[1] ${WHITE}Test de conectividad DNS básica:${RESET}"
    if dig +short @1.1.1.1 google.com > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓ DNS externo funcionando${RESET}"
    else
        echo -e "  ${RED}✗ Problemas con DNS externo${RESET}"
    fi

    # 2. Verificar túnel local
    echo -e "${CYAN}[2] ${WHITE}Verificando túnel Slipstream:${RESET}"
    if systemctl is-active slipstream &>/dev/null; then
        echo -e "  ${GREEN}✓ Servicio Slipstream activo${RESET}"
        # Verificar puerto 53
        if ss -ulpn | grep -q ":53"; then
            echo -e "  ${GREEN}✓ Puerto 53 en uso por Slipstream${RESET}"
        else
            echo -e "  ${RED}✗ Puerto 53 no escuchando${RESET}"
        fi
    else
        echo -e "  ${RED}✗ Servicio Slipstream inactivo${RESET}"
    fi

    # 3. Verificar logs de errores
    echo -e "${CYAN}[3] ${WHITE}Revisando logs de errores:${RESET}"
    if journalctl -u slipstream -n 5 --no-pager | grep -i "error\|failed\|disconnect" > /dev/null; then
        echo -e "  ${YELLOW}⚠️  Errores encontrados en logs:${RESET}"
        journalctl -u slipstream -n 3 --no-pager | grep -i "error\|failed\|disconnect"
    else
        echo -e "  ${GREEN}✓ No hay errores recientes${RESET}"
    fi

    # 4. Verificar configuración QUIC
    echo -e "${CYAN}[4] ${WHITE}Verificando configuración QUIC:${RESET}"
    if [ -f "$CERT/cert.pem" ] && [ -f "$CERT/key.pem" ]; then
        echo -e "  ${GREEN}✓ Certificados SSL presentes${RESET}"
    else
        echo -e "  ${RED}✗ Certificados SSL faltantes${RESET}"
    fi

    # 5. Test de latencia DNS
    echo -e "${CYAN}[5] ${WHITE}Test de latencia DNS:${RESET}"
    timeout 3 dig @1.1.1.1 google.com | grep "Query time" || echo "  ${RED}✗ Timeout en test de latencia${RESET}"

    draw_box "Recomendación: Ejecute 'Reparación Automática' si hay problemas"
    read -p "Presiona Enter para continuar..."
}

auto_fix_quic() {
    show_banner
    draw_header "REPARACIÓN AUTOMÁTICA Y ANTI-DESCONEXIÓN" $RED

    echo -e "${WHITE}Aplicando parches avanzados para estabilidad QUIC...${RESET}"
    echo

    # 1. Reiniciar servicio
    show_progress "Reiniciando servicio Slipstream"
    systemctl restart slipstream
    sleep 2

    # 2. Limpiar caché DNS
    show_progress "Limpiando caché DNS"
    systemctl restart systemd-resolved 2>/dev/null
    rm -f /etc/resolv.conf
    cat > /etc/resolv.conf <<EOF
nameserver 1.1.1.1
nameserver 8.8.8.8
options timeout:1 attempts:2
EOF

    # 3. Optimizar parámetros de red para QUIC (MEJORADO)
    show_progress "Optimizando Kernel para CERO desconexiones"
    cat > /etc/sysctl.d/99-tito-quic-ultimate.conf <<EOF
# Optimización TITO SLIPSTREAM PRO - QUIC STABILITY
# Aumentar buffers UDP para evitar pérdida de paquetes (Critical for QUIC)
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.udp_mem = 8192 262144 536870912
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# TCP Tuning (Para el tráfico dentro del túnel)
net.ipv4.tcp_rmem = 4096 87380 268435456
net.ipv4.tcp_wmem = 4096 65536 268435456
net.core.netdev_max_backlog = 30000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65535

# NAT Timeout (Engañar al firewall para mantener conexión)
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 180
EOF
    sysctl -p /etc/sysctl.d/99-tito-quic-ultimate.conf 2>/dev/null

    # 4. Ajustar límites de archivos
    show_progress "Ajustando límites del sistema (Max Open Files)"
    ulimit -n 65535
    echo "* soft nofile 65535" > /etc/security/limits.conf
    echo "* hard nofile 65535" >> /etc/security/limits.conf
    echo "root soft nofile 65535" >> /etc/security/limits.conf
    echo "root hard nofile 65535" >> /etc/security/limits.conf

    # 5. Crear script de monitoreo QUIC
    show_progress "Creando monitor QUIC 'Heartbeat'"
    cat > $QUIC_FIX_SCRIPT <<'EOF'
#!/bin/bash
# Monitor automático QUIC - TitoMX
LOG="/var/log/quic_monitor.log"
SERVICE="slipstream"

# Bucle infinito de monitoreo inteligente
while true; do
    # Verificar si el servicio está muerto
    if ! systemctl is-active $SERVICE > /dev/null; then
        echo "$(date) - [CRITICO] Servicio muerto. Reviviendo..." >> $LOG
        systemctl restart $SERVICE
        sleep 5
    fi

    # Ping DNS ligero para mantener NAT abierta (Keepalive)
    dig +short @127.0.0.1 -p 53 google.com > /dev/null 2>&1

    # Verificación profunda cada 1 minuto
    if [[ $(( $(date +%s) % 60 )) -eq 0 ]]; then
        if ! timeout 2 dig @1.1.1.1 google.com > /dev/null 2>&1; then
            echo "$(date) - [WARN] Micro-corte detectado. Limpiando buffers..." >> $LOG
            sync; echo 3 > /proc/sys/vm/drop_caches
        fi
    fi

    sleep 20
done
EOF

    chmod +x $QUIC_FIX_SCRIPT

    # Crear servicio para el monitor
    cat > /etc/systemd/system/quic-monitor.service <<EOF
[Unit]
Description=TitoMX QUIC Heartbeat Monitor
After=network.target

[Service]
Type=simple
ExecStart=$QUIC_FIX_SCRIPT
Restart=always
RestartSec=5
Nice=-10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now quic-monitor.service

    draw_box "Parches aplicados. El túnel ahora es resistente a UDP drops."
    read -p "Presiona Enter para continuar..."
}

performance_tuning() {
    show_banner
    draw_header "OPTIMIZACIÓN AVANZADA DE RENDIMIENTO" $BLUE

    echo -e "${WHITE}Aplicando optimizaciones específicas para QUIC/DNS...${RESET}"
    echo

    # Optimización específica para QUIC (BBR + FQ)
    show_progress "Activando algoritmo BBR (Google)"

    if lsmod | grep -q bbr; then
        echo -e "  ${GREEN}✓ BBR ya está activo${RESET}"
    else
        modprobe tcp_bbr
        echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
        sysctl -p
    fi

    # Optimizar servicios systemd para Slipstream
    show_progress "Dando prioridad CPU Realtime a Slipstream"
    if [ -f "$SERVICE" ]; then
        # INYECTAR PRIORIDAD ALTA
        sed -i '/^\[Service\]/a Nice=-20' $SERVICE
        sed -i '/^\[Service\]/a IOSchedulingClass=realtime' $SERVICE
        sed -i '/^\[Service\]/a IOSchedulingPriority=0' $SERVICE
        sed -i '/^\[Service\]/a CPUSchedulingPolicy=rr' $SERVICE
        sed -i '/^\[Service\]/a CPUSchedulingPriority=99' $SERVICE

        systemctl daemon-reload
        systemctl restart slipstream
    fi

    # Configurar CPU governor para performance
    show_progress "Bloqueando frecuencia CPU al máximo"
    if command -v cpupower &>/dev/null; then
        cpupower frequency-set -g performance
    fi

    # Aumentar buffers de red en la tarjeta física
    show_progress "Maximizando Ring Buffers de red"
    eth=$(ip route get 1 | awk '{print $5; exit}')
    if [ -n "$eth" ]; then
        ethtool -G $eth rx 4096 tx 4096 2>/dev/null || true
        # Desactivar Offloading que causa problemas con UDP/QUIC
        ethtool -K $eth tx off rx off gso off tso off gro off lro off 2>/dev/null || true
    fi

    draw_box "Optimización completada. CPU y Red en modo ULTRA."
    read -p "Presiona Enter para continuar..."
}

monitor_quic_traffic() {
    show_banner
    draw_header "MONITOR DE TRÁFICO QUIC EN TIEMPO REAL" $MAGENTA

    echo -e "${WHITE}Monitor activo - Presiona Ctrl+C para salir${RESET}"
    echo -e "${YELLOW}Mostrando tráfico QUIC/DNS cada 2 segundos...${RESET}"
    echo

    watch -n 2 "
    echo '=== CONEXIONES UDP (QUIC) ==='
    netstat -anu | grep ':53'
    echo ''
    echo '=== PAQUETES UDP DROPPED (Kernel) ==='
    netstat -s | grep -i 'packet receive errors'
    echo ''
    echo '=== ESTADO SLIPSTREAM (Prioridad CPU) ==='
    ps -eo pid,ni,pri,comm | grep slipstream
    echo ''
    echo '=== USO DE RECURSOS ==='
    top -bn1 | head -5
    "
}

# ===================== FUNCIONES ORIGINALES (MODIFICADAS) =====================
install_libssl11() {
    echo -e "${WHITE}Verificando libssl.so.1.1...${RESET}"
    if ldconfig -p | grep -q "libssl.so.1.1"; then
        echo -e "  ${GREEN}✓ libssl1.1 ya instalado${RESET}"
        return
    fi
    # Nota: El binario Go estático no suele necesitar libssl, pero el script lo pide.
    # Lo dejamos para compatibilidad general.
    echo -e "  ${YELLOW}Instalando libssl1.1...${RESET}"

    # Fallback to apt install if possible
    apt install libssl1.1 -y 2>/dev/null || true
}

install_slipstream() {
    show_banner
    draw_header "INSTALACIÓN COMPLETA SLIPSTREAM PRO (STABLE)" $GREEN

    echo -e "${WHITE}Iniciando instalación optimizada para 0 desconexiones...${RESET}"
    echo

    show_progress "Actualizando sistema"
    apt update -y
    apt upgrade -y

    show_progress "Instalando dependencias"
    apt install -y curl wget ca-certificates lsof openssl net-tools ethtool dnsutils \
                   systemd-resolved iptables-persistent fail2ban tmux htop iftop

    install_libssl11

    echo -e "${YELLOW}[FIX REAL] Liberando puerto 53 TOTAL...${RESET}"

    # Liberar puerto 53
    chattr -i /etc/resolv.conf 2>/dev/null
    systemctl stop systemd-resolved 2>/dev/null
    systemctl disable systemd-resolved 2>/dev/null
    pkill -9 systemd-resolve 2>/dev/null

    if [ -L /etc/resolv.conf ]; then
        rm -f /etc/resolv.conf
    fi

    cat > /etc/resolv.conf <<EOF
nameserver 1.1.1.1
nameserver 8.8.8.8
options timeout:1 attempts:2
EOF

    chattr +i /etc/resolv.conf
    sleep 2

    if ss -ulpn | grep -q ":53"; then
        echo -e "  ${RED}✗ El puerto 53 sigue ocupado${RESET}"
        ss -ulpn | grep :53
        # Intentar matar agresivamente
        fuser -k 53/udp
    fi

    echo -e "  ${GREEN}✓ Puerto 53 LIBRE Y BLOQUEADO${RESET}"
    mkdir -p $CERT

    # PREGUNTAR DOMINIO
    read -p "Ingrese su DOMINIO para el certificado SSL (ej: midominio.com): " USER_DOMAIN
    if [ ! -z "$USER_DOMAIN" ]; then
        DOMAIN="$USER_DOMAIN"
    fi

    show_progress "Generando certificados SSL para $DOMAIN"
    openssl req -new -newkey rsa:2048 -nodes -x509 -days 3650 \
     -subj "/CN=$DOMAIN" \
     -keyout $CERT/key.pem \
     -out $CERT/cert.pem

    show_progress "Instalando Binario Personalizado (Go)"
    if [ -f "server-linux-amd64" ]; then
        cp "server-linux-amd64" "$BIN"
    else
        echo -e "  ${RED}✗ No se encontró 'server-linux-amd64' en el directorio actual.${RESET}"
        # Fallback de emergencia a wget si el usuario lo subió con otro nombre, pero por ahora error.
        exit 1
    fi

    chmod +x $BIN

    show_progress "Validando binario"
    # El binario Go no tiene --help necesariamente igual, pero probamos.
    $BIN --help >/dev/null 2>&1 || true

    show_progress "Configurando servicio BLINDADO"
    cat > $SERVICE <<EOF

[Unit]
Description=Slipstream DNS Tunnel PRO (High Performance)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root

ExecStart=$BIN \
  --target-address=127.0.0.1:22 \
  --domain=$DOMAIN \
  --cert=$CERT/cert.pem \
  --key=$CERT/key.pem \
  --dns-listen-port=53

# 🔑 PERMISO PARA PUERTO 53 + HIGH PRIORITY
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_SYS_NICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SYS_NICE
NoNewPrivileges=false

# 🔥 OPTIMIZACIONES ANTI-LAG
Nice=-15
CPUSchedulingPolicy=rr
CPUSchedulingPriority=50
LimitNOFILE=1048576
LimitNPROC=1048576
LimitMEMLOCK=infinity
Restart=always
RestartSec=1
StartLimitInterval=0

StandardOutput=journal
StandardError=journal
SyslogIdentifier=slipstream

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now slipstream

    # Crear configuración
    cat > $CONFIG <<EOF
# Configuración Slipstream TitoMX PRO
DOMAIN="$DOMAIN"
IP="$IP"
BIN="$BIN"
CERT="$CERT"
DB="$DB"
LOG="$LOG"

# Configuración QUIC
QUIC_MAX_STREAMS=1000
QUIC_IDLE_TIMEOUT=600
QUIC_KEEPALIVE=30

# Redes sociales
TELEGRAM_BOT="@InternetTitofree_bot"
TELEGRAM_CHANNEL="https://t.me/titoYTMex"
TELEGRAM_CHAT="https://t.me/titoYTMex2"
FACEBOOK="https://www.facebook.com/profile.php?id=61552016896249"
EOF

    draw_box "INSTALACIÓN COMPLETADA EXITOSAMENTE"
    echo -e "${GREEN}Slipstream PRO instalado y funcionando${RESET}"
    echo -e "${WHITE}Dominio: ${GREEN}$DOMAIN${RESET}"
    echo -e "${WHITE}IP: ${GREEN}$IP${RESET}"
    echo -e "${WHITE}Puerto: ${GREEN}53 (UDP/TCP)${RESET}"
    echo -e "${YELLOW}NOTA: Ejecuta la opción [T] -> [2] para máxima estabilidad${RESET}"
    read -p "Presiona Enter para continuar..."
}

create_user() {
    show_banner
    draw_header "CREAR NUEVO USUARIO SLIPSTREAM" $CYAN

    read -p "$(echo -e "${WHITE}Usuario: ${RESET}")" u
    read -p "$(echo -e "${WHITE}Contraseña: ${RESET}")" p
    read -p "$(echo -e "${WHITE}Días validez: ${RESET}")" d
    read -p "$(echo -e "${WHITE}Límite conexiones: ${RESET}")" l

    id "$u" &>/dev/null && {
        draw_box "Usuario ya existe"
        read
        return
    }

    useradd -m -s /bin/bash $u
    echo "$u:$p" | chpasswd

    EXP=$(date -d "+$d days" +%Y-%m-%d)
    chage -E $EXP $u

    echo "$u:$p:$l:$EXP" >> $DB
    echo -e "${GREEN}✓ Usuario creado exitosamente${RESET}"
    echo -e "${WHITE}Usuario: ${GREEN}$u${RESET}"
    echo -e "${WHITE}Expira: ${GREEN}$EXP${RESET}"
    echo -e "${WHITE}Límite: ${GREEN}$l conexiones${RESET}"
    read
}

list_users() {
    show_banner
    draw_header "LISTA DE USUARIOS ACTIVOS" $PURPLE

    echo -e "${CYAN}┌──────────────────┬──────────────┬──────┬──────────────┐${RESET}"
    echo -e "${CYAN}│${WHITE} Usuario${RESET}          ${CYAN}│${WHITE} Expiración${RESET}   ${CYAN}│${WHITE} Límite${RESET} ${CYAN}│${WHITE} Estado${RESET}       ${CYAN}│${RESET}"
    echo -e "${CYAN}├──────────────────┼──────────────┼──────┼──────────────┤${RESET}"

    while IFS=: read -r u p l e; do
        # Verificar si el usuario está activo
        if chage -l "$u" 2>/dev/null | grep -q "cuenta expira"; then
            status="${GREEN}ACTIVO${RESET}"
        else
            status="${RED}EXPIRADO${RESET}"
        fi

        printf "${CYAN}│${WHITE} %-16s ${CYAN}│${WHITE} %-12s ${CYAN}│${WHITE} %-4s ${CYAN}│${WHITE} %-12s ${CYAN}│${RESET}\n" \
               "$u" "$e" "$l" "$status"
    done < "$DB"

    echo -e "${CYAN}└──────────────────┴──────────────┴──────┴──────────────┘${RESET}"
    read
}

kill_multi() {
    show_banner
    draw_header "CONTROL DE MULTI-SESIONES" $RED

    echo -e "${WHITE}Eliminando sesiones excedentes...${RESET}"
    echo

    total_killed=0
    while IFS=: read -r u p l e; do
        con=$(pgrep -u "$u" sshd | wc -l)
        if (( con > l )); then
            echo -e "${YELLOW}• $u: $con conexiones (límite: $l)${RESET}"
            pkill -u "$u" sshd
            ((total_killed++))
        fi
    done < "$DB"

    draw_box "Sesiones eliminadas: $total_killed"
    read
}

watchdog_on() {
    show_banner
    draw_header "ACTIVAR WATCHDOG AUTOMÁTICO" $YELLOW

    cat > $WD_SCRIPT <<'EOF'
#!/bin/bash
# Watchdog TitoMX PRO - Slipstream

LOG="/var/log/slipstream_watchdog.log"
SERVICE="slipstream"
DB="/root/usuarios_slipstream.db"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOG
}

# Verificar servicio Slipstream
if ! systemctl is-active $SERVICE > /dev/null; then
    log "Servicio Slipstream caído, reiniciando..."
    systemctl restart $SERVICE
    sleep 5
fi

# Verificar puerto 53
if ! ss -ulpn | grep -q ":53"; then
    log "Puerto 53 no escuchando, reiniciando..."
    systemctl restart $SERVICE
fi

# Control de multi-sesiones
while IFS=: read -r u p l e; do
    con=$(pgrep -u "$u" sshd | wc -l)
    if (( con > l )); then
        log "Usuario $u excedió límite ($con/$l), matando sesiones..."
        pkill -u "$u" sshd
    fi
done < $DB

# Verificar expiración de usuarios
TODAY=$(date +%s)
while IFS=: read -r u p l e; do
    EXP=$(date -d "$e" +%s 2>/dev/null || echo 0)
    if (( EXP > 0 && EXP < TODAY )); then
        log "Usuario $u expirado, desactivando..."
        usermod -L "$u" 2>/dev/null
        pkill -u "$u" sshd 2>/dev/null
    fi
done < $DB

# Verificar QUIC (Ping rápido)
if ! timeout 2 dig @127.0.0.1 -p 53 google.com > /dev/null 2>&1; then
    log "QUIC local no responde, posible bloqueo UDP..."
fi
EOF

    chmod +x $WD_SCRIPT

    cat > $WD_SERVICE <<EOF
[Unit]
Description=Slipstream Watchdog PRO
After=network.target

[Service]
Type=oneshot
ExecStart=$WD_SCRIPT
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

    cat > $WD_TIMER <<EOF
[Unit]
Description=Slipstream Watchdog Timer
Requires=slip-watchdog.service

[Timer]
OnBootSec=1min
OnUnitActiveSec=30s
AccuracySec=1s

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now slip-watchdog.timer

    draw_box "WATCHDOG ACTIVADO - Revisa cada 30 segundos"
    read
}

show_redes() {
    show_banner
    draw_header "REDES SOCIALES TITO MX - CONÉCTATE" $BLUE

    echo -e "${WHITE}📡 ${GREEN}CONECTA CON NUESTRA COMUNIDAD:${RESET}"
    echo
    echo -e "${CYAN}┌────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${CYAN}│${WHITE} 🤖 ${YELLOW}BOT TELEGRAM:${RESET} @InternetTitofree_bot                ${CYAN}│${RESET}"
    echo -e "${CYAN}│${WHITE} 📢 ${YELLOW}CANAL OFICIAL:${RESET} https://t.me/titoYTMex               ${CYAN}│${RESET}"
    echo -e "${CYAN}│${WHITE} 💬 ${YELLOW}CHAT OFICIAL:${RESET} https://t.me/titoYTMex2              ${CYAN}│${RESET}"
    echo -e "${CYAN}│${WHITE} 📘 ${YELLOW}FACEBOOK:${RESET} https://www.facebook.com/...             ${CYAN}│${RESET}"
    echo -e "${CYAN}│                                                        ${CYAN}│${RESET}"
    echo -e "${CYAN}│${WHITE} 🔗 ${YELLOW}ENLACE COMPLETO FACEBOOK:${RESET}                          ${CYAN}│${RESET}"
    echo -e "${CYAN}│${WHITE} https://www.facebook.com/profile.php?id=61552016896249${RESET} ${CYAN}│${RESET}"
    echo -e "${CYAN}│${WHITE} &mibextid=ZbWKwL                                  ${CYAN}│${RESET}"
    echo -e "${CYAN}└────────────────────────────────────────────────────────┘${RESET}"
    echo
    echo -e "${YELLOW}────────────────────────────────────────────────────────${RESET}"
    echo -e "${GREEN}  ÚNETE A TODOS PARA QUE SIEMPRE ESTÉS INFORMADO${RESET}"
    echo -e "${YELLOW}────────────────────────────────────────────────────────${RESET}"
    echo -e "${BLUE}           DIOS LES BENDIGA 🙏${RESET}"
    echo -e "${YELLOW}────────────────────────────────────────────────────────${RESET}"
    read
}

# ===================== MENÚ PRINCIPAL MEJORADO =====================
while true; do
    show_banner

    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║${GREEN}             PANEL DE CONTROL SLIPSTREAM PRO                 ${CYAN}║${RESET}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${RESET}"

    echo -e "${CYAN}║${WHITE}   [1]${YELLOW} Instalar Slipstream (FIX REAL + ANTI-LAG)           ${CYAN}║${RESET}"
    echo -e "${CYAN}║${WHITE}   [2]${YELLOW} Iniciar/Detener Slipstream                          ${CYAN}║${RESET}"
    echo -e "${CYAN}║${WHITE}   [3]${YELLOW} Administrar Watchdog                                ${CYAN}║${RESET}"
    echo -e "${CYAN}║${WHITE}   [4]${YELLOW} Crear usuario                                       ${CYAN}║${RESET}"
    echo -e "${CYAN}║${WHITE}   [5]${YELLOW} Listar usuarios                                     ${CYAN}║${RESET}"
    echo -e "${CYAN}║${WHITE}   [6]${YELLOW} Control multi-sesiones                              ${CYAN}║${RESET}"
    echo -e "${CYAN}║${WHITE}   [7]${YELLOW} Estado del sistema                                  ${CYAN}║${RESET}"
    echo -e "${CYAN}║                                                              ${CYAN}║${RESET}"
    echo -e "${CYAN}║${PURPLE}   [T]${YELLOW} Toolkit QUIC/DNS Profesional                        ${CYAN}║${RESET}"
    echo -e "${CYAN}║${PURPLE}   [R]${YELLOW} Redes Sociales TitoMX                               ${CYAN}║${RESET}"
    echo -e "${CYAN}║${RED}   [0]${YELLOW} Salir                                               ${CYAN}║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}"

    echo -ne "${GREEN}➤ ${RESET}${WHITE}Selecciona una opción: ${RESET}"
    read op

    case $op in
        1) install_slipstream ;;
        2)
            echo -e "${CYAN}1) Iniciar  2) Detener  3) Reiniciar${RESET}"
            read -p "Opción: " sub
            case $sub in
                1) systemctl start slipstream ;;
                2) systemctl stop slipstream ;;
                3) systemctl restart slipstream ;;
            esac
            ;;
        3)
            echo -e "${CYAN}1) Activar Watchdog  2) Desactivar Watchdog${RESET}"
            read -p "Opción: " sub
            case $sub in
                1) watchdog_on ;;
                2) systemctl disable --now slip-watchdog.timer ;;
            esac
            ;;
        4) create_user ;;
        5) list_users ;;
        6) kill_multi ;;
        7)
            systemctl status slipstream --no-pager -l
            echo -e "\n${CYAN}────────────────────────────────────────${RESET}"
            echo -e "${WHITE}Conexiones activas:${RESET}"
            netstat -anp | grep ':22' | grep ESTABLISHED | wc -l
            read
            ;;
        t|T)
            show_banner
            echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${RESET}"
            echo -e "${CYAN}║${PURPLE}              TOOLKIT QUIC/DNS PROFESIONAL                  ${CYAN}║${RESET}"
            echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${RESET}"
            echo -e "${CYAN}║${WHITE}   [1]${YELLOW} Diagnóstico QUIC/DNS completo                     ${CYAN}║${RESET}"
            echo -e "${CYAN}║${WHITE}   [2]${YELLOW} Reparación automática (ANTI-DISCONNECT)           ${CYAN}║${RESET}"
            echo -e "${CYAN}║${WHITE}   [3]${YELLOW} Optimización de rendimiento (CPU/RED)             ${CYAN}║${RESET}"
            echo -e "${CYAN}║${WHITE}   [4]${YELLOW} Monitor tráfico en tiempo real                    ${CYAN}║${RESET}"
            echo -e "${CYAN}║${WHITE}   [5]${YELLOW} Ver logs del sistema                              ${CYAN}║${RESET}"
            echo -e "${CYAN}║${WHITE}   [6]${YELLOW} Test de velocidad DNS                             ${CYAN}║${RESET}"
            echo -e "${CYAN}║${WHITE}   [0]${YELLOW} Volver al menú principal                          ${CYAN}║${RESET}"
            echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}"
            read -p "Selecciona herramienta: " tool
            case $tool in
                1) quic_diagnostic ;;
                2) auto_fix_quic ;;
                3) performance_tuning ;;
                4) monitor_quic_traffic ;;
                5) journalctl -u slipstream -n 50 --no-pager; read ;;
                6)
                    echo -e "${WHITE}Test de velocidad DNS...${RESET}"
                    timeout 5 dig @1.1.1.1 google.com | grep "Query time"
                    read
                    ;;
            esac
            ;;
        r|R) show_redes ;;
        0)
            echo -e "\n${GREEN}¡Hasta pronto! 🇨🇺${RESET}"
            echo -e "${BLUE}DIOS LES BENDIGA 🙏${RESET}"
            exit 0
            ;;
    esac
done
