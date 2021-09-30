package scan

import (
	"context"
	"crypto/x509"
)

type Certer interface {
	Read(context.Context, chan<- *x509.Certificate, chan<- error)
}

type SliceCerter []*x509.Certificate

var _ Certer = (SliceCerter)(nil)

func (sc SliceCerter) Read(ctx context.Context, cout chan<- *x509.Certificate, eout chan<- error) {
	for _, s := range sc {
		cout <- s
	}
}

type ChanCerter struct {
	certs chan *x509.Certificate
	errs  chan error
}

var _ Certer = (*ChanCerter)(nil)

func (cc ChanCerter) Read(ctx context.Context, cout chan<- *x509.Certificate, eout chan<- error) {
	var (
		// temp variables
		cert *x509.Certificate
		err  error
		// nillable chan variables
		co chan<- *x509.Certificate
		eo chan<- error

		// are inputs closed?
		ok bool
	)
	ci, ei := cc.certs, cc.errs

	for {
		// This select safely multiplexes both sends and receives on
		select {
		case cert, ok = <-ci:
			if !ok {
				return
			}
			co = cout
			ci = nil
		case err, ok = <-ei:
			if !ok {
				return
			}
			eo = eout
			ei = nil
		case eo <- err:
			ei = cc.errs
			eo = nil
		case co <- cert:
			ci = cc.certs
			co = nil
		}
	}
}

// Close closes the underlying channels
func (cc ChanCerter) Close() error {
	close(cc.certs)
	close(cc.errs)
	return nil
}

// NewChanCerter returns a new ChanCerter
func NewChanCerter() ChanCerter {
	return ChanCerter{
		certs: make(chan *x509.Certificate),
		errs:  make(chan error),
	}
}
