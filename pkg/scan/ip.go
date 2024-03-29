package scan

import (
	"context"
	"fmt"
	"net"
	"time"
)

// An IPScanner can scan a single IP
type IPScanner struct {
	IP      net.IP
	Ports   []int16
	Scans   []ConnScanner
	Timeout time.Duration
}

var _ Scanner = (*IPScanner)(nil)

var DefaultTimeout = time.Second

func (is IPScanner) Scan(ctx context.Context) (Certer, error) {
	cc := NewChanCerter()
	if is.Timeout == time.Duration(0) {
		is.Timeout = DefaultTimeout
	}

	go func() {
		defer cc.Close()

		for _, port := range is.Ports {
			addr := fmt.Sprintf("%s:%d", is.IP, port)
			conn, err := net.DialTimeout("tcp", addr, is.Timeout)
			if err != nil {
				cc.errs <- err
				continue
			}

			for _, scan := range is.Scans {
				conn.SetDeadline(time.Now().Add(is.Timeout))

				crt, err := scan.ScanConn(ctx, conn)
				if err != nil {
					cc.errs <- err
					continue
				}
				crt.Read(ctx, cc.certs, cc.errs)
			}

			err = conn.Close()
			if err != nil {
				cc.errs <- err
			}
		}
	}()

	return cc, nil
}
