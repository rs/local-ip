package localip

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
)

var testIP = net.ParseIP("203.0.113.0")

type Server struct {
	CertManager
	Self net.IP
}

func (s *Server) Serve() error {
	if err := s.Init(s); err != nil {
		return err
	}

	done := make(chan error, 1)

	ds := &dns.Server{Addr: ":53", Net: "udp", Handler: s}
	defer ds.Shutdown()
	go func() {
		err := ds.ListenAndServe()
		done <- err
	}()

	l, err := net.Listen("tcp", ":443")
	defer l.Close()
	if err != nil {
		return err
	}
	go func() {
		tl := tls.NewListener(l, &tls.Config{
			GetCertificate: s.GetCertificate,
		})
		err := http.Serve(tl, s)
		done <- err
	}()

	s.loadOrRefresh()

	for {
		select {
		case <-time.After(24 * time.Hour):
			s.loadOrRefresh()
		case err := <-done:
			return err
		}
	}
}

func (s *Server) Present(domain, token, keyAuth string) error {
	fqdn, value := dns01.GetRecord(domain, keyAuth)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dnsChallenges == nil {
		s.dnsChallenges = map[string][]string{}
	}
	s.dnsChallenges[fqdn] = append(s.dnsChallenges[fqdn], value)
	return nil
}

func (s *Server) CleanUp(domain, token, keyAuth string) error {
	fqdn, value := dns01.GetRecord(domain, keyAuth)
	s.mu.Lock()
	defer s.mu.Unlock()
	values := s.dnsChallenges[fqdn]
	for i := len(values) - 1; i >= 0; i-- {
		if values[i] == value {
			values = append(values[:i], values[i+1:]...)
		}
	}
	if len(values) > 0 {
		s.dnsChallenges[fqdn] = values
	} else {
		delete(s.dnsChallenges, fqdn)
	}
	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/cert.pem":
		s.mu.RLock()
		defer s.mu.RUnlock()
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(s.certPem)
	case "/key.pem":
		s.mu.RLock()
		defer s.mu.RUnlock()
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(s.keyPem)
	default:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	}
}

func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) != 1 {
		return
	}
	domain := dns.CanonicalName(s.Domain)
	qtype := r.Question[0].Qtype
	qname := dns.CanonicalName(r.Question[0].Name)
	log.Printf("Q: %s %s", dns.TypeToString[qtype], qname)
	if !dns.IsSubDomain(domain, qname) {
		return
	}
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = false
	var ip net.IP
	switch qname {
	case domain, "ns." + domain:
		ip = s.Self
	case "whoami." + domain:
		ip = getAddrIP(w.RemoteAddr())
	case "test." + domain:
		ip = testIP
	default:
		ip = extractSubDomainIP(qname, domain)
		if !allowed(ip) {
			ip = nil
		}
	}
	if qname == domain && qtype == dns.TypeSOA {
		m.Answer = append(m.Answer, &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   qname,
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    86400,
			},
			Ns:      "ns." + domain,
			Mbox:    "ns." + domain,
			Refresh: 1200,
			Retry:   300,
			Expire:  1209600,
			Minttl:  300,
		})
	} else if qname == domain && qtype == dns.TypeNS {
		m.Answer = append(m.Answer, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   qname,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Ns: "ns." + domain,
		})
	} else if ip != nil {
		if qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    86400,
				},
				A: ip,
			})
		}
	} else {
		s.mu.RLock()
		challenges, found := s.dnsChallenges[qname]
		s.mu.RUnlock()
		if found {
			if qtype == dns.TypeTXT {
				for _, c := range challenges {
					m.Answer = append(m.Answer, &dns.TXT{
						Hdr: dns.RR_Header{
							Name:   qname,
							Rrtype: dns.TypeTXT,
							Class:  dns.ClassINET,
							Ttl:    120,
						},
						Txt: []string{c},
					})
				}
			}
		} else {
			m.Rcode = dns.RcodeNameError
		}
	}
	_ = w.WriteMsg(m)
}

func extractSubDomainIP(qname, domain string) net.IP {
	// Get the subdomain part of the qname
	subDomain := strings.TrimSuffix(qname, "."+domain)
	// Remove any prefix with double hyphens
	if idx := strings.LastIndex(subDomain, "--"); idx > 0 {
		subDomain = subDomain[idx+2:]
	}
	if strings.IndexByte(subDomain, '.') != -1 {
		return nil
	}
	// Replace hyphens with dots (IPv4 only)
	ipStr := strings.ReplaceAll(subDomain, "-", ".")
	return net.ParseIP(ipStr)
}

func allowed(ip net.IP) bool {
	if ip.IsPrivate() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] == 64 {
		// Allow CGNAT private space
		return true
	}
	return false
}

func getAddrIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	switch addr := addr.(type) {
	case *net.UDPAddr:
		return addr.IP
	case *net.TCPAddr:
		return addr.IP
	default:
		return nil
	}
}
