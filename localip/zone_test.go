package localip

import (
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestParseZoneFile(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		zone    string
		want    Zone
		wantErr bool
	}{
		{"glue", "example.com.", `
sub 30 IN NS ns.sub

ns.sub 30 IN A 1.2.3.4
ns.sub 30 IN A 1.2.3.5
		`,
			Zone{
				&dns.NS{Hdr: dns.RR_Header{
					Name:   "sub.example.com.",
					Rrtype: dns.TypeNS,
					Class:  dns.ClassINET,
					Ttl:    30,
				}, Ns: "ns.sub.example.com."},
				&dns.A{Hdr: dns.RR_Header{
					Name:   "ns.sub.example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    30,
				}, A: net.ParseIP("1.2.3.4")},
				&dns.A{Hdr: dns.RR_Header{
					Name:   "ns.sub.example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    30,
				}, A: net.ParseIP("1.2.3.5")},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseZone(tt.domain, "file", strings.NewReader(tt.zone))
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseZoneFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseZoneFile(): \n%v\nwant:\n%v", got, tt.want)
			}
		})
	}
}

func TestZone_handleZone(t *testing.T) {
	tests := []struct {
		name string
		zone string
		req  *dns.Msg
		want *dns.Msg
	}{
		{"delegation", `
sub 30 IN NS ns.sub

ns.sub 30 IN A 1.2.3.4
ns.sub 30 IN A 1.2.3.5
				`,
			&dns.Msg{
				Question: []dns.Question{
					{
						Name:   "label.sub.test.com.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			},
			&dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:            0,
					Authoritative: true,
					Response:      true,
				},
				Compress: true,
				Question: []dns.Question{
					{
						Name:   "label.sub.test.com.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
				Ns: []dns.RR{
					&dns.NS{
						Hdr: dns.RR_Header{
							Name:   "label.sub.test.com.",
							Rrtype: dns.TypeNS,
							Class:  dns.ClassINET,
							Ttl:    30,
						},
						Ns: "ns.sub.test.com.",
					},
				},
				Extra: []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "ns.sub.test.com.",
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    30,
						},
						A: net.ParseIP("1.2.3.4"),
					},
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "ns.sub.test.com.",
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    30,
						},
						A: net.ParseIP("1.2.3.5"),
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			z, err := parseZone("test.com.", "file", strings.NewReader(tt.zone))
			if err != nil {
				t.Fatalf("parseZone() error = %v", err)
			}
			if got := z.handleZone(tt.req); got.String() != tt.want.String() {
				t.Errorf("Zone.handleZone():\n%v\nwant:\n%v", got, tt.want)
			}
		})
	}
}
