package scan

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
)

// A HandshakeScanner can scan a connection with multiple DNSNames
type HandshakeScanner struct {
	Configs []*tls.Config
}

// ScanConn scans a net.Conn for TLS certificates by attempting a direct TLS
// handshake.
func (hs HandshakeScanner) ScanConn(conn net.Conn) (Certer, error) {
	defer func() {
		if err := recover(); err != nil {
			log.Fatal(err)
		}
	}()
	cs := make([]*x509.Certificate, 0, len(hs.Configs)*3/2)

	for _, config := range hs.Configs {
		conn := tls.Client(conn, config)
		if err := conn.Handshake(); err != nil {
			return SliceCerter(cs), err
		}

		// TODO we might want to keep the chain here.
		cs = append(cs, conn.ConnectionState().PeerCertificates[0])

		if err := conn.CloseWrite(); err != nil {
			return SliceCerter(cs), err
		}

	}

	return SliceCerter(cs), nil
}
