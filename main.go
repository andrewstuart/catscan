package main

import "astuart.co/catscan/pkg/scan"

func main() {
	d := scan.AXFRScanner{
		DNSServer: "192.168.16.5:53",
	}
}
