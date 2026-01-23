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
	serverAddr := flag.String("server", "127.0.0.1:5301", "Remote QUIC server address")
	flag.Parse()

	// TLS Config - Insecure for now as we use self-signed mostly.
	// TODO: Add CA loading if needed.
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

	// SOCKS5 Negotiation
	// 1. Read Version + NMethods
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	ver, nMethods := buf[0], buf[1]
	if ver != 5 {
		return // Only SOCKS5
	}

	// 2. Read Methods
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// 3. Reply: No Auth (0x00)
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 4. Read Request
	// [VER][CMD][RSV][ATYP][DST.ADDR][DST.PORT]
	// We need to parse this to reconstruct it or send it efficiently.
	// Actually, our protocol needs (Addr, Port).
	// So we must parse it.

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	// cmd := header[1]
	atyp := header[3]

	if header[1] != 0x01 { // CMD must be CONNECT
		// Reply Command not supported
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
		// Address type not supported
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	bufPort := make([]byte, 2)
	if _, err := io.ReadFull(conn, bufPort); err != nil {
		return
	}
	destPort = binary.BigEndian.Uint16(bufPort)

	// Now we have addr and destPort.
	// Open Stream to Server.
	stream, err := client.GetStream()
	if err != nil {
		log.Printf("Failed to get stream: %v", err)
		// Reply Server Failure
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer stream.Close()

	// Send Request to Server
	if err := protocol.WriteRequest(stream, addr, destPort); err != nil {
		log.Printf("Failed to write request: %v", err)
		return
	}

	// Assuming Server is ready to pipe if WriteRequest succeeded (mostly).
	// Reply SOCKS5 Success to Client
	// [VER][REP][RSV][ATYP][BND.ADDR][BND.PORT]
	// We just send 0.0.0.0:0 as bound addr
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
