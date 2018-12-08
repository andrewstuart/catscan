package scan

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestDNS(t *testing.T) {
	asrt := assert.New(t)
	a := AXFRScanner{
		recGet: func() (chan *dns.Envelope, error) {
			ch := make(chan *dns.Envelope)
			go func() {
				select {
				case ch <- &dns.Envelope{}:
				case <-time.After(2 * time.Second):
					t.Fail("dns filter timed out")
				}
			}()

			return ch, nil
		},
	}
	c, err := a.Scan()
}
