package scan

import (
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
