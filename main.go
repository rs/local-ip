package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/rs/local-ip/localip"
)

func main() {
	domain := flag.String("domain", "", "Base domain to use for local-ip service")
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

	der, err := ioutil.ReadFile(*key)
	if err != nil {
		log.Fatalf("read private key: %v", err)
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
	}

	if err := s.Serve(); err != nil {
		log.Fatal(err)
	}
}
