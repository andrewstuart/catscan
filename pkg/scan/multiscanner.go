package scan

import (
	"context"
	"fmt"
	"sync"
)

// MultiScanner can aggregate multiple scanners concurrently
type MultiScanner struct {
	Scanners    []Scanner
	Concurrency int
}

var _ Scanner = (*MultiScanner)(nil)

// Scan implements Scan for multiple Scanners concurrently
func (mc MultiScanner) Scan(ctx context.Context) (Certer, error) {
	if mc.Concurrency < 1 {
		return nil, fmt.Errorf("concurrency (%d) cannot be less than 1", mc.Concurrency)
	}

	conc := make(chan struct{}, mc.Concurrency)

	cc := NewChanCerter()
	var wg sync.WaitGroup
	wg.Add(len(mc.Scanners))

	go func() {
		wg.Wait()
		cc.Close()
	}()

	for _, s := range mc.Scanners {
		go func(s Scanner) {
			defer func() {
				wg.Done()
				<-conc
			}()
			conc <- struct{}{}

			certer, err := s.Scan(ctx)
			if err != nil {
				cc.errs <- err
				return
			}

			certer.Read(ctx, cc.certs, cc.errs)
		}(s)
	}

	return cc, nil
}
