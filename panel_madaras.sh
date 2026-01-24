#!/bin/bash
# ==================================================
#       MADARAS QUIC ENGINE - GO EDITION PANEL
#       (Optimized for Stability & Performance)
# ==================================================

# Configuración básica
BIN_DIR="/usr/local/bin"
BIN_NAME="slipstream-server"
BIN_PATH="$BIN_DIR/$BIN_NAME"
SERVICE_FILE="/etc/systemd/system/slipstream.service"
WORK_DIR="/opt/quic-tunnel"
CERT_DIR="/etc/madaras/certs"
DB_FILE="/etc/madaras/users.db"

# Colores (Sin parpadeo)
CYAN="\e[96m"
GREEN="\e[92m"
RED="\e[91m"
YELLOW="\e[93m"
PURPLE="\e[95m"
BLUE="\e[94m"
WHITE="\e[97m"
RESET="\e[0m"

# Verificar root
[[ $EUID -ne 0 ]] && echo -e "${RED}[ERROR]${RESET} Ejecuta como root" && exit 1

mkdir -p /etc/madaras
touch "$DB_FILE"

# ===================== FUNCIONES DE DISEÑO =====================
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
    echo -ne "${WHITE}• $1...${RESET}"
    sleep 0.5
    echo -e "${GREEN} ✓${RESET}"
}

# ===================== BANNER =====================
show_banner() {
    clear
    echo -e "${BLUE}"
    cat << "EOF"
███╗   ███╗ █████╗ ██████╗  █████╗ ██████╗  █████╗ ███████╗
████╗ ████║██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝
██╔████╔██║███████║██║  ██║███████║██████╔╝███████║███████╗
██║╚██╔╝██║██╔══██║██║  ██║██╔══██║██╔══██╗██╔══██║╚════██║
██║ ╚═╝ ██║██║  ██║██████╔╝██║  ██║██║  ██║██║  ██║███████║
╚═╝     ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
EOF
    echo -e "${RESET}"
    draw_header "QUIC GO ENGINE - TITAN EDITION" $PURPLE

    # Estados
    if systemctl is-active slipstream &>/dev/null; then
        STATUS="${GREEN}● ACTIVO${RESET}"
    else
        STATUS="${RED}● INACTIVO${RESET}"
    fi
    echo -e "${CYAN}║ ${WHITE}Estado Servicio${RESET}       ║ $STATUS                          ${CYAN}║${RESET}"

    PORT_CHECK=$(ss -ulpn | grep :53 | grep slipstream)
    if [ -n "$PORT_CHECK" ]; then
        P53="${GREEN}● ESCUCHANDO (UDP)${RESET}"
    else
        P53="${RED}● CERRADO${RESET}"
    fi
    echo -e "${CYAN}║ ${WHITE}Puerto 53${RESET}             ║ $P53                          ${CYAN}║${RESET}"

    CONNS=$(netstat -anu | grep :53 | grep ESTABLISHED | wc -l)
    # Nota: UDP no tiene "ESTABLISHED" real, esto es aproximado o conteo de sockets conectados
    echo -e "${CYAN}║ ${WHITE}Conexiones UDP${RESET}        ║ ${YELLOW}$CONNS${RESET}                                   ${CYAN}║${RESET}"
    echo -e "${CYAN}╚════════════════════════╩══════════════════════════════════════╝${RESET}"
    echo
}

# ===================== INSTALACIÓN =====================
install_go_server() {
    show_banner
    draw_header "INSTALACIÓN DEL MOTOR GO (QUIC)" $GREEN

    show_progress "Preparando entorno"
    # Instalar Go si no existe
    if ! command -v go &> /dev/null; then
        echo -e "${YELLOW}Instalando Go 1.23...${RESET}"
        wget -q https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
        rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo "export PATH=\$PATH:/usr/local/go/bin" >> ~/.bashrc
    fi

    # Instalar dependencias del sistema (net-tools para netstat)
    show_progress "Instalando net-tools"
    apt-get install -y net-tools

    # Crear directorios
    mkdir -p "$WORK_DIR/cmd/server" "$WORK_DIR/pkg/protocol"

    # Escribir código fuente (Embedded)
    show_progress "Generando código fuente Go"

    cat <<EOF > "$WORK_DIR/go.mod"
module github.com/jules/quic-tunnel

go 1.23

require (
	github.com/quic-go/quic-go v0.48.2
	golang.org/x/net v0.33.0
)
EOF

    cat <<EOF > "$WORK_DIR/pkg/protocol/protocol.go"
package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	CmdConnect = 0x01
)

const (
	AddrTypeIPv4   = 0x01
	AddrTypeDomain = 0x03
	AddrTypeIPv6   = 0x04
)

func WriteRequest(w io.Writer, addr string, port uint16) error {
	if _, err := w.Write([]byte{CmdConnect}); err != nil {
		return err
	}
	ip := net.ParseIP(addr)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			if _, err := w.Write([]byte{AddrTypeIPv4}); err != nil { return err }
			if _, err := w.Write(ip4); err != nil { return err }
		} else {
			if _, err := w.Write([]byte{AddrTypeIPv6}); err != nil { return err }
			if _, err := w.Write(ip.To16()); err != nil { return err }
		}
	} else {
		if len(addr) > 255 { return fmt.Errorf("domain too long") }
		if _, err := w.Write([]byte{AddrTypeDomain}); err != nil { return err }
		if _, err := w.Write([]byte{byte(len(addr))}); err != nil { return err }
		if _, err := w.Write([]byte(addr)); err != nil { return err }
	}
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	if _, err := w.Write(portBuf); err != nil { return err }
	return nil
}

func ReadRequest(r io.Reader) (cmd byte, addr string, port uint16, err error) {
	buf1 := make([]byte, 1)
	if _, err := io.ReadFull(r, buf1); err != nil { return 0, "", 0, err }
	cmd = buf1[0]

	if _, err := io.ReadFull(r, buf1); err != nil { return 0, "", 0, err }
	addrType := buf1[0]

	switch addrType {
	case AddrTypeIPv4:
		bufIP := make([]byte, 4)
		if _, err := io.ReadFull(r, bufIP); err != nil { return 0, "", 0, err }
		addr = net.IP(bufIP).String()
	case AddrTypeIPv6:
		bufIP := make([]byte, 16)
		if _, err := io.ReadFull(r, bufIP); err != nil { return 0, "", 0, err }
		addr = net.IP(bufIP).String()
	case AddrTypeDomain:
		if _, err := io.ReadFull(r, buf1); err != nil { return 0, "", 0, err }
		lenDomain := int(buf1[0])
		bufDomain := make([]byte, lenDomain)
		if _, err := io.ReadFull(r, bufDomain); err != nil { return 0, "", 0, err }
		addr = string(bufDomain)
	default:
		return 0, "", 0, fmt.Errorf("unknown address type: %d", addrType)
	}

	bufPort := make([]byte, 2)
	if _, err := io.ReadFull(r, bufPort); err != nil { return 0, "", 0, err }
	port = binary.BigEndian.Uint16(bufPort)

	return cmd, addr, port, nil
}
EOF

    # Main Server Code con Custom DNS Support
    cat <<EOF > "$WORK_DIR/cmd/server/main.go"
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/jules/quic-tunnel/pkg/protocol"
	"github.com/quic-go/quic-go"
)

var (
	customResolver *net.Resolver
)

func main() {
	addr := flag.String("addr", ":53", "UDP address to listen on")
	certFile := flag.String("cert", "", "Path to certificate file")
	keyFile := flag.String("key", "", "Path to key file")
	dnsServer := flag.String("dns", "", "Custom DNS server (e.g., 8.8.8.8:53)")
	flag.Parse()

	if *dnsServer != "" {
		log.Printf("Using custom DNS resolver: %s", *dnsServer)
		customResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: 10 * time.Second,
				}
				return d.DialContext(ctx, "udp", *dnsServer)
			},
		}
	}

	tlsConf, err := generateTLSConfig(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Failed to setup TLS: %v", err)
	}

	listener, err := quic.ListenAddr(*addr, tlsConf, &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	log.Printf("Server listening on %s (UDP)", *addr)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn quic.Connection) {
	defer conn.CloseWithError(0, "closed")
	log.Printf("New connection from %s", conn.RemoteAddr())

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("AcceptStream error from %s: %v", conn.RemoteAddr(), err)
			return
		}
		go handleStream(stream)
	}
}

func handleStream(stream quic.Stream) {
	defer stream.Close()

	cmd, targetAddr, targetPort, err := protocol.ReadRequest(stream)
	if err != nil {
		log.Printf("Failed to read request: %v", err)
		return
	}

	if cmd != protocol.CmdConnect {
		log.Printf("Unsupported command: %d", cmd)
		return
	}

	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)
	log.Printf("Connecting to %s", target)

	var targetConn net.Conn
	var dialErr error

	dialer := net.Dialer{
		Timeout: 10 * time.Second,
		Resolver: customResolver,
	}
	targetConn, dialErr = dialer.Dial("tcp", target)

	if dialErr != nil {
		log.Printf("Failed to dial %s: %v", target, dialErr)
		return
	}
	defer targetConn.Close()

	go func() {
		defer stream.CancelRead(0)
		defer targetConn.Close()
		io.Copy(targetConn, stream)
	}()

	io.Copy(stream, targetConn)
}

func generateTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"quic-tunnel"},
		}, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil { return nil, err }
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil { return nil, err }
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil { return nil, err }
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-tunnel"},
	}, nil
}
EOF

    show_progress "Compilando Servidor"
    cd "$WORK_DIR"
    /usr/local/go/bin/go mod tidy
    /usr/local/go/bin/go build -o "$BIN_NAME" cmd/server/main.go

    # Instalación
    show_progress "Deteniendo servicios conflictivos"
    systemctl stop slipstream 2>/dev/null
    fuser -k 53/udp 2>/dev/null
    fuser -k 53/tcp 2>/dev/null

    cp "$BIN_NAME" "$BIN_PATH"
    chmod +x "$BIN_PATH"

    # Generar Certificados Dummy si no existen
    mkdir -p "$CERT_DIR"
    if [ ! -f "$CERT_DIR/fullchain.pem" ]; then
        openssl req -x509 -newkey rsa:4096 -keyout "$CERT_DIR/privkey.pem" -out "$CERT_DIR/fullchain.pem" -days 3650 -nodes -subj "/CN=madaras.work.gd" >/dev/null 2>&1
    fi

    # Preguntar por DNS Personalizado
    read -p "Ingrese DNS Personalizado para Resolver (ej: 1.1.1.1:53, Enter para Default): " C_DNS
    DNS_FLAG=""
    if [ ! -z "$C_DNS" ]; then
        DNS_FLAG="-dns $C_DNS"
    fi

    show_progress "Creando Servicio SystemD"
    cat > $SERVICE_FILE <<EOF
[Unit]
Description=Madaras Go QUIC Engine
After=network.target

[Service]
Type=simple
User=root
LimitNOFILE=1048576
ExecStart=$BIN_PATH -addr :53 -cert $CERT_DIR/fullchain.pem -key $CERT_DIR/privkey.pem $DNS_FLAG
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable slipstream
    systemctl start slipstream

    draw_box "INSTALACIÓN COMPLETADA - PUERTO 53 UDP"
    echo -e "${GREEN}El motor Go está corriendo.${RESET}"
    read -p "Presiona Enter para continuar..."
}

install_manual_binary() {
    show_banner
    draw_header "INSTALACIÓN MANUAL (BINARIO LOCAL)" $YELLOW

    LOCAL_BIN="./server-linux-amd64"
    if [ ! -f "$LOCAL_BIN" ]; then
        echo -e "${RED}Error: No encuentro el archivo '$LOCAL_BIN' en la carpeta actual.${RESET}"
        read -p "Presiona Enter..."
        return
    fi

    show_progress "Deteniendo servicios conflictivos"
    systemctl stop slipstream 2>/dev/null
    systemctl disable systemd-resolved 2>/dev/null
    systemctl stop systemd-resolved 2>/dev/null
    fuser -k 53/udp 2>/dev/null

    # Restaurar DNS del VPS (Crucial porque matamos systemd-resolved)
    rm -f /etc/resolv.conf
    echo "nameserver 1.1.1.1" > /etc/resolv.conf
    echo "nameserver 8.8.8.8" >> /etc/resolv.conf

    show_progress "Instalando Binario"
    cp "$LOCAL_BIN" "$BIN_PATH"
    chmod +x "$BIN_PATH"

    mkdir -p "$CERT_DIR"
    if [ ! -f "$CERT_DIR/fullchain.pem" ]; then
        openssl req -x509 -newkey rsa:4096 -keyout "$CERT_DIR/privkey.pem" -out "$CERT_DIR/fullchain.pem" -days 3650 -nodes -subj "/CN=madaras.work.gd" >/dev/null 2>&1
    fi

    show_progress "Creando Servicio SystemD"
    cat > $SERVICE_FILE <<EOF
[Unit]
Description=Madaras Go QUIC Engine
After=network.target

[Service]
Type=simple
User=root
LimitNOFILE=1048576
ExecStart=$BIN_PATH -addr :53 -cert $CERT_DIR/fullchain.pem -key $CERT_DIR/privkey.pem
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable slipstream
    systemctl start slipstream

    draw_box "INSTALACIÓN MANUAL COMPLETADA"
    echo -e "${GREEN}Servicio activo usando tu binario local.${RESET}"
    read -p "Enter..."
}

# ===================== GESTIÓN DE USUARIOS =====================
create_user() {
    show_banner
    draw_header "CREAR USUARIO (SSH Tunnel)" $CYAN

    # Nota: Como es un túnel SOCKS que redirige a SSH local (según lógica anterior), creamos usuario de sistema.
    read -p "Usuario: " u
    read -p "Contraseña: " p
    read -p "Días: " d

    if id "$u" &>/dev/null; then
        echo -e "${RED}El usuario ya existe.${RESET}"
    else
        useradd -M -s /bin/false "$u"
        echo "$u:$p" | chpasswd
        EXP=$(date -d "+$d days" +%Y-%m-%d)
        chage -E $EXP "$u"
        echo "$u:$EXP" >> "$DB_FILE"
        echo -e "${GREEN}Usuario creado.${RESET}"
    fi
    read -p "Enter..."
}

list_users() {
    show_banner
    draw_header "USUARIOS" $PURPLE
    echo -e "${WHITE}Lista de usuarios SSH (Sistema):${RESET}"
    cat "$DB_FILE"
    read -p "Enter..."
}

# ===================== HERRAMIENTAS =====================
auto_fix() {
    show_banner
    draw_header "REPARACIÓN AUTOMÁTICA" $YELLOW

    show_progress "Reiniciando Servicio"
    systemctl restart slipstream

    show_progress "Limpiando Caché DNS"
    systemctl restart systemd-resolved 2>/dev/null

    show_progress "Optimizando Kernel (BBR)"
    if ! lsmod | grep -q bbr; then
        echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
        sysctl -p
    fi

    draw_box "Reparación Finalizada"
    read -p "Enter..."
}

monitor_quic() {
    watch -n 1 "echo '=== ESTADO QUIC UDP :53 ==='; netstat -anu | grep :53; echo ''; echo '=== PROCESO GO ==='; ps aux | grep $BIN_NAME | grep -v grep"
}

# ===================== MENÚ PRINCIPAL =====================
while true; do
    show_banner
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║${WHITE}   [1]${YELLOW} Instalar/Actualizar Motor Go (Port 53)              ${CYAN}║${RESET}"
    echo -e "${CYAN}║${WHITE}   [2]${YELLOW} Reiniciar Servicio                                  ${CYAN}║${RESET}"
    echo -e "${CYAN}║${WHITE}   [3]${YELLOW} Crear Usuario SSH                                   ${CYAN}║${RESET}"
    echo -e "${CYAN}║${WHITE}   [4]${YELLOW} Ver Usuarios                                        ${CYAN}║${RESET}"
    echo -e "${CYAN}║${WHITE}   [5]${YELLOW} Auto Fix & Tune (BBR)                               ${CYAN}║${RESET}"
    echo -e "${CYAN}║${WHITE}   [6]${YELLOW} Monitor en Tiempo Real                              ${CYAN}║${RESET}"
    echo -e "${CYAN}║${WHITE}   [8]${YELLOW} Instalación Manual (Binario Local)                  ${CYAN}║${RESET}"
    echo -e "${CYAN}║${WHITE}   [0]${YELLOW} Salir                                               ${CYAN}║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}"
    read -p "Opción: " op

    case $op in
        1) install_go_server ;;
        2) systemctl restart slipstream; echo -e "${GREEN}Reiniciado.${RESET}"; sleep 1 ;;
        3) create_user ;;
        4) list_users ;;
        5) auto_fix ;;
        6) monitor_quic ;;
        8) install_manual_binary ;;
        0) exit 0 ;;
    esac
done
