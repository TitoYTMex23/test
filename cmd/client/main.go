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
	sess       quic.Connection
	mutex      sync.Mutex
}

func NewTunnelClient(serverAddr string, tlsConf *tls.Config) *TunnelClient {
	return &TunnelClient{
		serverAddr: serverAddr,
		tlsConf:    tlsConf,
	}
}

func (c *TunnelClient) GetStream() (quic.Stream, error) {
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
	localAddr := flag.String("listen", ":8080", "Local SOCKS5 address")
	serverAddr := flag.String("server", "", "Remote QUIC server address (e.g., 1.2.3.4:53)")
	resolverAddr := flag.String("resolver", "", "Alias for -server")
	domain := flag.String("domain", "", "SNI Domain for TLS handshake (e.g., example.com)")

	// Flags for compatibility/unused but present in some scripts
	_ = flag.String("tcp-listen-port", "", "Ignored (compatibility)")
	_ = flag.Int("keep-alive-interval", 0, "Ignored (compatibility)")

	flag.Parse()

	targetServer := *serverAddr
	if targetServer == "" {
		targetServer = *resolverAddr
	}
	if targetServer == "" {
		targetServer = "127.0.0.1:53"
		log.Println("No server specified, using default: 127.0.0.1:53")
	}

	// TLS Config
	tlsConf := &tls.Config{
		InsecureSkipVerify: true, // Self-signed usually
		NextProtos:         []string{"quic-tunnel"},
		ServerName:         *domain, // SNI is crucial for obfuscation
	}

	client := NewTunnelClient(targetServer, tlsConf)

	listener, err := net.Listen("tcp", *localAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *localAddr, err)
	}
	log.Printf("SOCKS5 listening on %s", *localAddr)
	log.Printf("Forwarding to %s (SNI: %s)", targetServer, *domain)

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

	// SOCKS5 Negotiation
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	ver, nMethods := buf[0], buf[1]
	if ver != 5 {
		return // Only SOCKS5
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// Reply: No Auth (0x00)
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Read Request
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	atyp := header[3]

	if header[1] != 0x01 { // CMD must be CONNECT
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var addr string
	var destPort uint16

	switch atyp {
	case 0x01: // IPv4
		bufIP := make([]byte, 4)
		if _, err := io.ReadFull(conn, bufIP); err != nil {
			return
		}
		addr = net.IP(bufIP).String()
	case 0x03: // Domain
		bufLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, bufLen); err != nil {
			return
		}
		domainLen := int(bufLen[0])
		bufDomain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, bufDomain); err != nil {
			return
		}
		addr = string(bufDomain)
	case 0x04: // IPv6
		bufIP := make([]byte, 16)
		if _, err := io.ReadFull(conn, bufIP); err != nil {
			return
		}
		addr = net.IP(bufIP).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	bufPort := make([]byte, 2)
	if _, err := io.ReadFull(conn, bufPort); err != nil {
		return
	}
	destPort = binary.BigEndian.Uint16(bufPort)

	// Open Stream to Server
	stream, err := client.GetStream()
	if err != nil {
		log.Printf("Failed to get stream: %v", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer stream.Close()

	// Send Request to Server
	if err := protocol.WriteRequest(stream, addr, destPort); err != nil {
		log.Printf("Failed to write request: %v", err)
		return
	}

	// Reply SOCKS5 Success
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// Pipe
	go func() {
		defer stream.CancelRead(0)
		defer conn.Close()
		io.Copy(conn, stream)
	}()

	io.Copy(stream, conn)
}
