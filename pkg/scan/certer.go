package scan

import "crypto/x509"

type Certer interface {
	Read(chan<- *x509.Certificate, chan<- error)
}

type SliceCerter []*x509.Certificate

func (sc SliceCerter) Read(cout chan<- *x509.Certificate, eout chan<- error) {
	for _, s := range sc {
		cout <- s
	}
}

type ChanCerter <-chan *x509.Certificate

func (cc ChanCerter) Read(cout chan<- *x509.Certificate, eout chan<- error) {
	for s := range cc {
		cout <- s
	}
}
