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

	// Compatibility flags for panel scripts
	targetAddrIgnored := flag.String("target-address", "", "Target address (Ignored in SOCKS mode)")
	dnsListenPort := flag.String("dns-listen-port", "", "Alias for -addr port")
	domain := flag.String("domain", "", "Domain for SNI (informational)")

	flag.Parse()

	// Handle aliases
	listenAddr := *addr
	if *dnsListenPort != "" {
		listenAddr = ":" + *dnsListenPort
	}

	if *targetAddrIgnored != "" {
		log.Printf("Starting in SOCKS5 Dynamic Mode (ignoring fixed target: %s)", *targetAddrIgnored)
	}
	if *domain != "" {
		log.Printf("Serving for domain: %s", *domain)
	}

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

	listener, err := quic.ListenAddr(listenAddr, tlsConf, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	log.Printf("Server listening on %s (UDP)", listenAddr)

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
	dialer := net.Dialer{
		Timeout:  10 * time.Second,
		Resolver: customResolver,
	}

	targetConn, err = dialer.Dial("tcp", target)
	if err != nil {
		log.Printf("Failed to dial %s: %v", target, err)
		return
	}
	defer targetConn.Close()

	// Bidirectional copy
	go func() {
		defer stream.CancelRead(0)
		defer targetConn.Close()
		io.Copy(targetConn, stream)
	}()

	defer stream.Close()
	defer targetConn.Close()
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

	// Generate self-signed
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-tunnel"},
	}, nil
}
