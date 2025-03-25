package main

import (
	"flag"
	"log"
	"net"
	"os"

	"github.com/miekg/dns"
	"github.com/rs/local-ip/localip"
)

func main() {
	domain := flag.String("domain", "", "Base domain to use for local-ip service")
	zoneFile := flag.String("zone-file", "", "Path to the optional zone file for custom records to serve under the domain")
	self := flag.String("self", "", "Self IP")
	cacheDir := flag.String("cache-dir", "", "Path to the cache directory")
	email := flag.String("email", "", "ACME account")
	reg := flag.String("reg", "", "ACME reg URL")
	key := flag.String("key", "", "Path to private key")
	flag.Parse()
	selfIP := net.ParseIP(*self)
	if *domain == "" || selfIP == nil {
		flag.PrintDefaults()
		os.Exit(1)
	}

	der, err := os.ReadFile(*key)
	if err != nil {
		log.Fatalf("read private key: %v", err)
	}

	var zone []dns.RR
	if *zoneFile != "" {
		if zone, err = localip.ParseZoneFile(*domain, *zoneFile); err != nil {
			log.Fatalf("load zone file: %v", err)
		}
	}

	s := localip.Server{
		CertManager: localip.CertManager{
			Email:  *email,
			Reg:    *reg,
			Key:    der,
			Domain: *domain,
			Cache:  localip.FileCache(*cacheDir),
		},
		Self: selfIP,
		Zone: zone,
	}

	if err := s.Serve(); err != nil {
		log.Fatal(err)
	}
}
