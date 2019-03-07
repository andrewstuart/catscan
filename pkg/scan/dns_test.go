package scan

// func TestDNS(t *testing.T) {
// 	asrt := assert.New(t)
// 	a := AXFRScanner{
// 		recGet: func() (chan dns.RR, error) {
// 			ch := make(chan dns.RR)
// 			go func() {
// 				select {
// 				case ch <- &dns.RR_Header{}:
// 				case <-time.After(2 * time.Second):
// 					t.Fatal("dns filter timed out")
// 				}
// 			}()

// 			return ch, nil
// 		},
// 	}
// 	c, err := a.Scan()
// }
