package scan

import "net"

// An IPScanner can scan a single IP
type IPScanner struct {
	IP    net.IP
	Ports []int16
	Scans []ConnScanner
}

func (is IPScanner) Scan() (Certer, error) {
	panic("foo")
}
