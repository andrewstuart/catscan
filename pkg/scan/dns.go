package scan

// AXFRScanner will query DNS records via AXFR and aggregate the results of
// each IP (and theirrelated DNS records) represented in the set of DNS
// records.
type AXFRScanner struct {
	DNSServer string
}

func (a AXFRScanner) Scan() (Certer, error) {
	panic("NYI")
}
