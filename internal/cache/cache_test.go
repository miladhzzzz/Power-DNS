package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func makeAnswer(name string, ttl uint32) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), dns.TypeA)

	resp := new(dns.Msg)
	resp.SetReply(req)
	rr, _ := dns.NewRR(dns.Fqdn(name) + " " + itoa(ttl) + " IN A 1.2.3.4")
	resp.Answer = append(resp.Answer, rr)
	return resp
}

func itoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	digits := []byte{}
	for v > 0 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
		v /= 10
	}
	return string(digits)
}

func TestSetGetRoundTrip(t *testing.T) {
	c := New(Options{MaxEntries: 10, MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Second})
	resp := makeAnswer("example.com", 300)
	c.Set("example.com.", dns.TypeA, resp)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	got, ok := c.Get(req, "example.com.", dns.TypeA)
	if !ok {
		t.Fatalf("expected cache hit")
	}
	if len(got.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(got.Answer))
	}
	if got.Id != req.Id {
		t.Fatalf("expected reply Id %d to match request Id %d", got.Id, req.Id)
	}
}

func TestExpiry(t *testing.T) {
	c := New(Options{MaxEntries: 10, MinTTL: 0, MaxTTL: time.Hour, NegativeTTL: time.Second})
	resp := makeAnswer("expiring.com", 0) // TTL 0 gets clamped up to MinTTL... but MinTTL is 0 here
	c.opts.MinTTL = 10 * time.Millisecond
	c.Set("expiring.com.", dns.TypeA, resp)

	time.Sleep(30 * time.Millisecond)

	req := new(dns.Msg)
	req.SetQuestion("expiring.com.", dns.TypeA)
	if _, ok := c.Get(req, "expiring.com.", dns.TypeA); ok {
		t.Fatalf("expected entry to have expired")
	}
}

func TestLRUEviction(t *testing.T) {
	c := New(Options{MaxEntries: 2, MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Second})
	c.Set("a.com.", dns.TypeA, makeAnswer("a.com", 300))
	c.Set("b.com.", dns.TypeA, makeAnswer("b.com", 300))
	c.Set("c.com.", dns.TypeA, makeAnswer("c.com", 300)) // should evict a.com (least recently used)

	req := new(dns.Msg)
	req.SetQuestion("a.com.", dns.TypeA)
	if _, ok := c.Get(req, "a.com.", dns.TypeA); ok {
		t.Fatalf("expected a.com to have been evicted")
	}
	if c.Len() != 2 {
		t.Fatalf("expected 2 entries, got %d", c.Len())
	}
}

func TestNegativeCaching(t *testing.T) {
	c := New(Options{MaxEntries: 10, MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Hour})
	req := new(dns.Msg)
	req.SetQuestion("nxdomain.com.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeNameError) // no Answer records

	c.Set("nxdomain.com.", dns.TypeA, resp)

	if _, ok := c.Get(req, "nxdomain.com.", dns.TypeA); !ok {
		t.Fatalf("expected negative response to be cached")
	}
}

func TestDelete(t *testing.T) {
	c := New(Options{MaxEntries: 10, MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Second})
	c.Set("del.com.", dns.TypeA, makeAnswer("del.com", 300))
	c.Delete("del.com.", dns.TypeA)

	req := new(dns.Msg)
	req.SetQuestion("del.com.", dns.TypeA)
	if _, ok := c.Get(req, "del.com.", dns.TypeA); ok {
		t.Fatalf("expected entry to be deleted")
	}
}
