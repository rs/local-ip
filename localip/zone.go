package localip

import (
	"io"
	"os"
	"sort"

	"github.com/miekg/dns"
)

type Zone []dns.RR

func ParseZoneFile(domain, path string) (Zone, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseZone(domain, path, f)
}

func parseZone(domain, path string, r io.Reader) (Zone, error) {
	zp := dns.NewZoneParser(r, domain, path)
	var zone []dns.RR
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		zone = append(zone, rr)
	}

	if err := zp.Err(); err != nil {
		return nil, err
	}
	return zone, nil
}

func (z Zone) ServeDNS(w dns.ResponseWriter, r *dns.Msg) (int, error) {
	m := z.handleZone(r)
	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeSuccess, nil
}

func (z Zone) handleZone(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Compress = true
	m.Rcode = dns.RcodeNameError
	qname := dns.CanonicalName(r.Question[0].Name)
	qnameLabelCount := dns.CountLabel(qname)
	qtype := r.Question[0].Qtype
	var extraNames []string
	for _, rr := range z {
		if dns.IsSubDomain(rr.Header().Name, qname) {
			switch t := rr.(type) {
			case *dns.NS:
				if qtype == dns.TypeNS && dns.CountLabel(rr.Header().Name) == qnameLabelCount {
					m.Answer = append(m.Answer, rr)
					m.Rcode = dns.RcodeSuccess
				} else {
					m.Ns = append(m.Ns, &dns.CNAME{Hdr: dns.RR_Header{
						Name:   qname,
						Rrtype: t.Hdr.Rrtype,
						Class:  t.Hdr.Class,
						Ttl:    t.Hdr.Ttl,
					}, Target: t.Ns})
					m.Rcode = dns.RcodeSuccess
				}
				extraNames = append(extraNames, t.Ns)
			case *dns.CNAME:
				if dns.CountLabel(rr.Header().Name) == qnameLabelCount {
					m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{
						Name:   qname,
						Rrtype: t.Hdr.Rrtype,
						Class:  t.Hdr.Class,
						Ttl:    t.Hdr.Ttl,
					}, Target: t.Target})
					extraNames = append(extraNames, t.Target)
					m.Rcode = dns.RcodeSuccess
				}
			default:
				if dns.CountLabel(rr.Header().Name) == qnameLabelCount {
					if rr.Header().Rrtype == qtype {
						m.Answer = append(m.Answer, rr)
						m.Rcode = dns.RcodeSuccess
					}
				}
			}
		}
	}
	if len(extraNames) > 0 {
		sort.Strings(extraNames)
		for i := 0; i < len(extraNames); i++ {
			if i+1 < len(extraNames) && extraNames[i] == extraNames[i+1] {
				continue
			}
			for _, rr := range z {
				if rr.Header().Name == extraNames[i] && rr.Header().Rrtype == qtype {
					m.Extra = append(m.Extra, rr)
				}
			}
		}
	}
	return m
}
