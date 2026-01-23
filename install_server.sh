#!/bin/bash

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}>>> Installing Go Environment...${NC}"
# Simple Go install for Linux AMD64 (common for servers)
if ! command -v go &> /dev/null; then
    wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo "export PATH=\$PATH:/usr/local/go/bin" >> ~/.bashrc
else
    echo "Go is already installed."
fi

WORK_DIR="/opt/quic-tunnel"
mkdir -p "$WORK_DIR/cmd/server"
mkdir -p "$WORK_DIR/pkg/protocol"

echo -e "${GREEN}>>> Creating Source Files...${NC}"

# go.mod
cat <<EOF > "$WORK_DIR/go.mod"
module github.com/jules/quic-tunnel

go 1.23

require (
	github.com/quic-go/quic-go v0.59.0
	golang.org/x/net v0.33.0
)
EOF

# pkg/protocol/protocol.go
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

// WriteRequest writes the connect request to the writer.
// Format: [Cmd(1)][AddrType(1)][Addr(var)][Port(2)]
func WriteRequest(w io.Writer, addr string, port uint16) error {
	// Write Command
	if _, err := w.Write([]byte{CmdConnect}); err != nil {
		return err
	}

	// Parse address
	ip := net.ParseIP(addr)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4
			if _, err := w.Write([]byte{AddrTypeIPv4}); err != nil {
				return err
			}
			if _, err := w.Write(ip4); err != nil {
				return err
			}
		} else {
			// IPv6
			if _, err := w.Write([]byte{AddrTypeIPv6}); err != nil {
				return err
			}
			if _, err := w.Write(ip.To16()); err != nil {
				return err
			}
		}
	} else {
		// Domain
		if len(addr) > 255 {
			return fmt.Errorf("domain too long")
		}
		if _, err := w.Write([]byte{AddrTypeDomain}); err != nil {
			return err
		}
		if _, err := w.Write([]byte{byte(len(addr))}); err != nil {
			return err
		}
		if _, err := w.Write([]byte(addr)); err != nil {
			return err
		}
	}

	// Write Port
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	if _, err := w.Write(portBuf); err != nil {
		return err
	}

	return nil
}

// ReadRequest reads the connect request from the reader.
func ReadRequest(r io.Reader) (cmd byte, addr string, port uint16, err error) {
	buf1 := make([]byte, 1)

	// Read Command
	if _, err := io.ReadFull(r, buf1); err != nil {
		return 0, "", 0, err
	}
	cmd = buf1[0]

	// Read AddrType
	if _, err := io.ReadFull(r, buf1); err != nil {
		return 0, "", 0, err
	}
	addrType := buf1[0]

	switch addrType {
	case AddrTypeIPv4:
		bufIP := make([]byte, 4)
		if _, err := io.ReadFull(r, bufIP); err != nil {
			return 0, "", 0, err
		}
		addr = net.IP(bufIP).String()
	case AddrTypeIPv6:
		bufIP := make([]byte, 16)
		if _, err := io.ReadFull(r, bufIP); err != nil {
			return 0, "", 0, err
		}
		addr = net.IP(bufIP).String()
	case AddrTypeDomain:
		if _, err := io.ReadFull(r, buf1); err != nil {
			return 0, "", 0, err
		}
		lenDomain := int(buf1[0])
		bufDomain := make([]byte, lenDomain)
		if _, err := io.ReadFull(r, bufDomain); err != nil {
			return 0, "", 0, err
		}
		addr = string(bufDomain)
	default:
		return 0, "", 0, fmt.Errorf("unknown address type: %d", addrType)
	}

	// Read Port
	bufPort := make([]byte, 2)
	if _, err := io.ReadFull(r, bufPort); err != nil {
		return 0, "", 0, err
	}
	port = binary.BigEndian.Uint16(bufPort)

	return cmd, addr, port, nil
}
EOF

# cmd/server/main.go
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

func main() {
	addr := flag.String("addr", ":53", "UDP address to listen on")
	certFile := flag.String("cert", "", "Path to certificate file")
	keyFile := flag.String("key", "", "Path to key file")
	flag.Parse()

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

func handleConnection(conn *quic.Conn) {
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

func handleStream(stream *quic.Stream) {
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

	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("Failed to dial %s: %v", target, err)
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

echo -e "${GREEN}>>> Compiling Server...${NC}"
cd "$WORK_DIR"
/usr/local/go/bin/go mod tidy
/usr/local/go/bin/go build -o slipstream-server cmd/server/main.go

echo -e "${GREEN}>>> Installing Binary...${NC}"
BIN_PATH="/usr/local/bin/slipstream-server"
systemctl stop slipstream 2>/dev/null
cp slipstream-server "$BIN_PATH"
chmod +x "$BIN_PATH"

echo -e "${GREEN}>>> Updating Service...${NC}"
CERT_DIR="/etc/madaras/certs"
mkdir -p "$CERT_DIR"

cat <<EOF > /etc/systemd/system/slipstream.service
[Unit]
Description=Madaras Titan Engine (Go Version)
After=network.target

[Service]
Type=simple
User=root
LimitNOFILE=1048576
ExecStart=$BIN_PATH -addr :53 -cert $CERT_DIR/fullchain.pem -key $CERT_DIR/privkey.pem
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable slipstream
systemctl start slipstream

echo -e "${GREEN}>>> Installation Complete! Service is running on UDP 53.${NC}"
