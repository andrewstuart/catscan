package main

import (
	"crypto/x509"
	"log"
	"time"

	"astuart.co/catscan/pkg/scan"
	"astuart.co/catscan/pkg/validate"
)

func main() {
	d := scan.AXFRScanner{
		DNSServer: "192.168.16.5:53",
		Domain:    "astuart.co",
		Ports:     []int16{443, 8443, 8080, 80},
	}

	c, err := d.Scan()
	if err != nil {
		log.Fatal(err)
	}

	certs, errs := make(chan *x509.Certificate), make(chan error)

	go func() {
		c.Read(certs, errs)
		close(certs)
		close(errs)
	}()

	v := validate.MultiValidator{
		validate.MinKeyStrength(2048),
		validate.ValidAt(time.Now()),
	}

	for {
		select {
		case c, ok := <-certs:
			if !ok {
				return
			}
			log.Println(c.Subject)
			err := v.Validate(c)
			if err != nil {
				log.Println(err)
			}
		case <-errs:
			// log.Println(err)
		}
	}

}
