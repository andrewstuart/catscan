package scan

import "github.com/Azure/azure-sdk-for-go/services/dns/mgmt/2017-10-01/dns"

type AzureDNSScanner struct {
	dns.BaseClient
}

// for rec := range recs {
// 	for _, rr := range rec.RR {
// 		switch rr := rr.(type) {
// 		case *dns.A:
// 			names[rr.Hdr.Name] = rr
// 			da, ok := ips[rr.A.String()]
// 			if !ok {
// 				// make an IP scanner and store it
// 				da = &IPScanner{
// 					IP:      rr.A,
// 					Ports:   a.Ports,
// 					Timeout: 10 * time.Second,
// 					Scans: []ConnScanner{&HandshakeScanner{
// 						Configs: []*tls.Config{},
// 					}},
// 				}
// 				ips[rr.A.String()] = da
// 			}
// 			hs := da.Scans[0].(*HandshakeScanner)
// 			hs.Configs = append(hs.Configs, &tls.Config{
// 				InsecureSkipVerify: true,
// 				ServerName:         rr.Hdr.Name,
// 			})
// 		case *dns.CNAME:
// 			cs = append(cs, rr)
// 		}
// 	}
// }

// for _, cname := range cs {
// 	if a, ok := names[cname.Target]; ok {
// 		hs := ips[a.A.String()].Scans[0].(*HandshakeScanner)
// 		hs.Configs = append(hs.Configs, &tls.Config{
// 			ServerName:         cname.Hdr.Name,
// 			InsecureSkipVerify: true,
// 		})
// 	}
// }

// mc := MultiScanner{
// 	Scanners:    make([]Scanner, 0, len(ips)),
// 	Concurrency: a.Concurrency,
// }
// if mc.Concurrency == 0 {
// 	mc.Concurrency = 400
// }

// for _, scanner := range ips {
// 	mc.Scanners = append(mc.Scanners, scanner)
// }
