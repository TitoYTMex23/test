#!/bin/bash

# Define colors
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}>>> Setting up Client Build Environment...${NC}"

WORK_DIR="quic-client-build"
mkdir -p "$WORK_DIR/cmd/client"
mkdir -p "$WORK_DIR/pkg/protocol"

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

# cmd/client/main.go
cat <<EOF > "$WORK_DIR/cmd/client/main.go"
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/jules/quic-tunnel/pkg/protocol"
	"github.com/quic-go/quic-go"
)

type TunnelClient struct {
	serverAddr string
	tlsConf    *tls.Config
	sess       *quic.Conn
	mutex      sync.Mutex
}

func NewTunnelClient(serverAddr string, tlsConf *tls.Config) *TunnelClient {
	return &TunnelClient{
		serverAddr: serverAddr,
		tlsConf:    tlsConf,
	}
}

func (c *TunnelClient) GetStream() (*quic.Stream, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.sess == nil {
		if err := c.dial(); err != nil {
			return nil, err
		}
	}

	stream, err := c.sess.OpenStreamSync(context.Background())
	if err != nil {
		log.Printf("Failed to open stream, redialing: %v", err)
		c.sess.CloseWithError(0, "reconnecting")
		if err := c.dial(); err != nil {
			return nil, err
		}
		return c.sess.OpenStreamSync(context.Background())
	}
	return stream, nil
}

func (c *TunnelClient) dial() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := quic.DialAddr(ctx, c.serverAddr, c.tlsConf, &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		return err
	}
	c.sess = sess
	return nil
}

func main() {
	localAddr := flag.String("listen", ":1080", "Local SOCKS5 address")
	serverAddr := flag.String("server", "127.0.0.1:53", "Remote QUIC server address")
	flag.Parse()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-tunnel"},
	}

	client := NewTunnelClient(*serverAddr, tlsConf)

	listener, err := net.Listen("tcp", *localAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *localAddr, err)
	}
	log.Printf("SOCKS5 listening on %s", *localAddr)
	log.Printf("Forwarding to %s", *serverAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleSocks5(conn, client)
	}
}

func handleSocks5(conn net.Conn, client *TunnelClient) {
	defer conn.Close()

	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil { return }
	ver, nMethods := buf[0], buf[1]
	if ver != 5 { return }
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil { return }
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil { return }

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil { return }
	atyp := header[3]

	if header[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var addr string
	var destPort uint16

	switch atyp {
	case 0x01:
		bufIP := make([]byte, 4)
		if _, err := io.ReadFull(conn, bufIP); err != nil { return }
		addr = net.IP(bufIP).String()
	case 0x03:
		bufLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, bufLen); err != nil { return }
		domainLen := int(bufLen[0])
		bufDomain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, bufDomain); err != nil { return }
		addr = string(bufDomain)
	case 0x04:
		bufIP := make([]byte, 16)
		if _, err := io.ReadFull(conn, bufIP); err != nil { return }
		addr = net.IP(bufIP).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	bufPort := make([]byte, 2)
	if _, err := io.ReadFull(conn, bufPort); err != nil { return }
	destPort = binary.BigEndian.Uint16(bufPort)

	stream, err := client.GetStream()
	if err != nil {
		log.Printf("Failed to get stream: %v", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer stream.Close()

	if err := protocol.WriteRequest(stream, addr, destPort); err != nil {
		log.Printf("Failed to write request: %v", err)
		return
	}

	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil { return }

	go func() {
		defer stream.CancelRead(0)
		defer conn.Close()
		io.Copy(conn, stream)
	}()

	io.Copy(stream, conn)
}
EOF

echo -e "${GREEN}>>> Compiling Client...${NC}"
cd "$WORK_DIR"
go mod tidy
# Cross compile for Android ARM64 (Termux) if running on Linux PC, else just build
if [ "$(uname -m)" != "aarch64" ]; then
    echo "Building for Android ARM64..."
    GOOS=android GOARCH=arm64 go build -o quic-client cmd/client/main.go
else
    go build -o quic-client cmd/client/main.go
fi

echo -e "${GREEN}>>> Build Complete!${NC}"
echo "Binary is located at: $WORK_DIR/quic-client"
echo "Transfer this binary to your Termux device."
echo "Run it with: ./quic-client -server YOUR_SERVER_IP:53"
