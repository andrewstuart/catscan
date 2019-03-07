package validate

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	multierror "github.com/hashicorp/go-multierror"
)

// A CertValidator can apply some validation logic to a certificate
type CertValidator interface {
	Validate(*x509.Certificate) error
}

// A MultiValidator can perform multiple validations on the same certificate
type MultiValidator []CertValidator

// Validate checks all the subvalidations and returns a hashicorp multierror
// containing any/all violations discovered.
func (m MultiValidator) Validate(c *x509.Certificate) error {
	var err error
	for _, m := range m {
		if e := m.Validate(c); e != nil {
			err = multierror.Append(e)
		}
	}
	return err
}

// MinKeyStrength checks that the key strength is at least the number given.
type MinKeyStrength int

// Validate checks the strength of the key in bits
func (m MinKeyStrength) Validate(c *x509.Certificate) error {
	switch key := c.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.Size()*8 < int(m) {
			return fmt.Errorf("key strength %d is less than required (%d)", key.Size()*8, m)
		}
	}
	return nil
}

// ValidAt checks that the represented time.Time falls between the
// certificate's NotAfter and NotBefore properties.
type ValidAt time.Time

// Validate checks expiration and maturity
func (v ValidAt) Validate(c *x509.Certificate) error {
	if time.Time(v).Before(c.NotBefore) {
		return fmt.Errorf("cert date %s is not yet valid", c.NotBefore)
	}

	if time.Time(v).After(c.NotAfter) {
		return fmt.Errorf("cert date %s is expired", c.NotAfter)
	}

	return nil
}
