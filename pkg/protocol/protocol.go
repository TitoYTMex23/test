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
