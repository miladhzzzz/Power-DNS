package filter

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestBanListContainsIranianRange(t *testing.T) {
	b, err := NewBanList([]string{"10.10.34.0/24"})
	if err != nil {
		t.Fatalf("NewBanList: %v", err)
	}
	for _, ip := range []string{"10.10.34.34", "10.10.34.35", "10.10.34.36", "10.10.34.1"} {
		if !b.ContainsIP(net.ParseIP(ip)) {
			t.Errorf("expected %s to be banned", ip)
		}
	}
	if b.ContainsIP(net.ParseIP("8.8.8.8")) {
		t.Error("8.8.8.8 must not be banned")
	}
}

func TestContainsAnswer(t *testing.T) {
	b, err := NewBanList([]string{"10.10.34.0/24"})
	if err != nil {
		t.Fatalf("NewBanList: %v", err)
	}
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "youtube.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("10.10.34.35").To4()},
	}
	if got := b.ContainsAnswer(msg); got != "10.10.34.35" {
		t.Errorf("ContainsAnswer = %q, want 10.10.34.35", got)
	}

	clean := new(dns.Msg)
	clean.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("93.184.216.34").To4()},
	}
	if got := b.ContainsAnswer(clean); got != "" {
		t.Errorf("clean answer flagged as poisoned: %s", got)
	}
}

func TestBareIPAccepted(t *testing.T) {
	b, err := NewBanList([]string{"10.10.34.34"})
	if err != nil {
		t.Fatalf("NewBanList: %v", err)
	}
	if !b.ContainsIP(net.ParseIP("10.10.34.34")) {
		t.Error("bare IP should be treated as /32")
	}
	if b.ContainsIP(net.ParseIP("10.10.34.35")) {
		t.Error("sibling IP must not match /32 ban")
	}
}
