package localip

import (
	"net"
	"reflect"
	"testing"
)

func Test_extractSubDomainIP(t *testing.T) {
	tests := []struct {
		qname  string
		domain string
		want   net.IP
	}{
		{"1-2-3-4.domain.com.", "domain.com.", net.ParseIP("1.2.3.4")},
		{"someting--1-2-3-4.domain.com.", "domain.com.", net.ParseIP("1.2.3.4")},
		{"someting--1-2-3-4.domain.com.", "other-domain.com.", nil},
		{"1.2.3.4.domain.com.", "domain.com.", nil},
	}
	for _, tt := range tests {
		t.Run(tt.qname, func(t *testing.T) {
			if got := extractSubDomainIP(tt.qname, tt.domain); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractSubDomainIP() = %v, want %v", got, tt.want)
			}
		})
	}
}
