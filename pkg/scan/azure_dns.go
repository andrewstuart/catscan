package scan

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

type AzureDNSScanner struct {
	Creds        azcore.TokenCredential // Usually fulfilled via azidentity credential
	Subscription string
}

func (a *AzureDNSScanner) Scan(ctx context.Context) (Certer, error) {
	groups := armresources.NewResourceGroupsClient(a.Subscription, a.Creds, nil)
	zoneCli := armdns.NewZonesClient(a.Subscription, a.Creds, nil)
	rsCli := armdns.NewRecordSetsClient(a.Subscription, a.Creds, nil)

	pg := groups.List(nil)

	cc := NewChanCerter()

	go func() {
		for pg.NextPage(ctx) {
			for _, g := range pg.PageResponse().Value {
				pg := zoneCli.ListByResourceGroup(*g.Name, &armdns.ZonesClientListByResourceGroupOptions{})

				for pg.NextPage(ctx) {
					for _, dns := range pg.PageResponse().Value {
						pg := rsCli.ListByDNSZone(*g.Name, *dns.Name, nil)
						for pg.NextPage(ctx) {
							for _, rec := range pg.PageResponse().Value {
								if rec.Properties.CnameRecord != nil {
									ips, err := net.LookupIP(*rec.Properties.CnameRecord.Cname)
									if err != nil {
										cc.errs <- fmt.Errorf("error looking up cname ips: %w", err)
									}
									for _, ip := range ips {
										sc := IPScanner{
											IP:      ip,
											Ports:   []int16{443},
											Timeout: 10 * time.Second,
											Scans: []ConnScanner{&HandshakeScanner{
												Configs: []*tls.Config{{
													InsecureSkipVerify: true,
													ServerName:         *rec.Name,
												}},
											}},
										}
										crt, err := sc.Scan(ctx)
										if err != nil {
											cc.errs <- fmt.Errorf("error scanning: %w", err)
											continue
										}
										go crt.Read(ctx, cc.certs, cc.errs)
									}
								}
								for _, aRec := range rec.Properties.ARecords {
									ip := net.ParseIP(*aRec.IPv4Address)
									sc := IPScanner{
										IP:      ip,
										Ports:   []int16{443},
										Timeout: 10 * time.Second,
										Scans: []ConnScanner{&HandshakeScanner{
											Configs: []*tls.Config{{
												InsecureSkipVerify: true,
												ServerName:         *rec.Name,
											}},
										}},
									}
									crt, err := sc.Scan(ctx)
									if err != nil {
										cc.errs <- fmt.Errorf("error scanning: %w", err)
										continue
									}
									go crt.Read(ctx, cc.certs, cc.errs)
								}
							}
						}
						if pg.Err() != nil {
							cc.errs <- fmt.Errorf("error paging dns records: %w", pg.Err())
						}
					}
				}
				if pg.Err() != nil {
					cc.errs <- fmt.Errorf("error paging dns zones: %w", pg.Err())
				}
			}
			if pg.Err() != nil {
				cc.errs <- fmt.Errorf("error paging resourcegroups: %w", pg.Err())
			}
		}
	}()
	return cc, nil
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
