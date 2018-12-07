package scan

import (
	"crypto/tls"
	"crypto/x509"
	"net"
)

// A Scanner implementation can return a stream of certificates, but may error
type Scanner interface {
	Scan() (Certer, error)
}

type ConnScanner interface {
	ScanConn(net.Conn) (Certer, error)
}

type ConnScanFunc func(net.Conn) ([]*x509.Certificate, error)

func (csf ConnScanFunc) ScanConn(conn net.Conn) (Certer, error) {
	slice, err := csf(conn)
	if err != nil {
		return nil, err
	}
	return SliceCerter(slice), nil
}

// A HandshakeScanner can scan a connection with multiple DNSNames
type HandshakeScanner struct {
	Configs []*tls.Config
}

// ScanConn scans a net.Conn for TLS certificates by attempting a direct TLS
// handshake.
func (hs HandshakeScanner) ScanConn(conn net.Conn) (Certer, error) {
	cs := make([]*x509.Certificate, 0, len(hs.Configs)*3/2)

	for _, config := range hs.Configs {
		conn := tls.Client(conn, config)
		if err := conn.Handshake(); err != nil {
			return SliceCerter(cs), err
		}

		// TODO we might want to keep the chain here.
		cs = append(cs, conn.ConnectionState().PeerCertificates[0])
	}

	return SliceCerter(cs), nil
}
