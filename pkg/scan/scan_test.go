package scan

import (
	"crypto/x509"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCertScanner(t *testing.T) {
	asrt := assert.New(t)

	cf := ConnScanFunc(func(_ net.Conn) ([]*x509.Certificate, error) {
		panic("Doesn't matter")
	})

	asrt.Implements((*ConnScanner)(nil), cf)
}
