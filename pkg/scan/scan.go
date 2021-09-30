package scan

import (
	"context"
	"crypto/x509"
	"net"
)

// Why scanner versus certer? IDK. I was probably crazy.
// Ideally just one interface.

// A Scanner implementation can return a stream of certificates, but may error
type Scanner interface {
	Scan(context.Context) (Certer, error)
}

type ConnScanner interface {
	ScanConn(context.Context, net.Conn) (Certer, error)
}

type ConnScanFunc func(context.Context, net.Conn) ([]*x509.Certificate, error)

var _ ConnScanner = (ConnScanFunc)(nil)

func (csf ConnScanFunc) ScanConn(ctx context.Context, conn net.Conn) (Certer, error) {
	slice, err := csf(ctx, conn)
	if err != nil {
		return nil, err
	}
	return SliceCerter(slice), nil
}
