package scan

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

// AXFRScanner will query DNS records via AXFR and aggregate the results of
// each IP (and theirrelated DNS records) represented in the set of DNS
// records.
type AXFRScanner struct {
	DNSServer string
	Domain    string

	Ports       []int16
	Scans       []ConnScanner
	Concurrency int

	// testing
	recGet func() (chan dns.RR, error)
}

func (a AXFRScanner) getRecs() (chan *dns.Envelope, error) {
	if a.recGet != nil {
		return a.getRecs()
	}
	t := &dns.Transfer{}
	m := &dns.Msg{}

	m.SetAxfr(fmt.Sprintf("%s.", strings.TrimRight(a.Domain, ".")))

	return t.In(m, a.DNSServer)
}

func (a AXFRScanner) Scan() (Certer, error) {
	recs, err := a.getRecs()
	if err != nil {
		return nil, errors.Wrap(err, "dns query error")
	}

	ips := map[string]*IPScanner{}
	names := map[string]*dns.A{}

	cs := []*dns.CNAME{}

	for rec := range recs {
		for _, rr := range rec.RR {
			switch rr := rr.(type) {
			case *dns.A:
				names[rr.Hdr.Name] = rr
				da, ok := ips[rr.A.String()]
				if !ok {
					// make an IP scanner and store it
					da = &IPScanner{
						IP:    rr.A,
						Ports: a.Ports,
						Scans: []ConnScanner{&HandshakeScanner{
							Configs: []*tls.Config{},
						}},
					}
					ips[rr.A.String()] = da
				}
				hs := da.Scans[0].(*HandshakeScanner)
				hs.Configs = append(hs.Configs, &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         rr.Hdr.Name,
				})
			case *dns.CNAME:
				cs = append(cs, rr)
			}
		}
	}

	for _, cname := range cs {
		if a, ok := names[cname.Target]; ok {
			hs := ips[a.A.String()].Scans[0].(*HandshakeScanner)
			hs.Configs = append(hs.Configs, &tls.Config{
				ServerName:         cname.Hdr.Name,
				InsecureSkipVerify: true,
			})
		}
	}

	mc := MultiScanner{
		Scanners:    make([]Scanner, 0, len(ips)),
		Concurrency: a.Concurrency,
	}
	if mc.Concurrency == 0 {
		mc.Concurrency = 400
	}

	for _, scanner := range ips {
		mc.Scanners = append(mc.Scanners, scanner)
	}

	return mc.Scan()
}
