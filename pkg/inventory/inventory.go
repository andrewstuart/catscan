package inventory

import "crypto/x509"

type Recorder interface {
	Record(*x509.Certificate) error
}
