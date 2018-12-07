package validate

import (
	"crypto/x509"

	multierror "github.com/hashicorp/go-multierror"
)

// A CertValidator can apply some validation logic to a certificate
type CertValidator interface {
	Validate(*x509.Certificate) error
}

type MultiValidator []*x509.Certificate

func (m MultiValidator) Validate(c *x509.Certificate) error {
	var err error
	for _, m := range m {
		if e := m.Validate(c); e != nil {
			err = multierror.Append(err)
		}
	}
	return err
}

type MinKeyStrength int

func (m MinKeyStrength) Validate(c *x509.Certificate) error {
	panic("NYI")
}
