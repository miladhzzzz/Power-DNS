// Package wire provides helpers for carrying raw DNS wire-format messages
// over HTTP, as specified by RFC 8484 (DNS Queries over HTTPS).
//
// v1 invented its own JSON shape for relayed answers
// (`{"domain": "...", "response": {"answer": [...]}}`) that only modeled A
// records: every other RR type (AAAA, CNAME, MX, TXT, ...) was silently
// dropped. v2 instead relays the exact bytes miekg/dns already produces, so
// answers of any record type survive the trip unmodified, and the relay
// endpoint doubles as a spec-compliant DoH server that any DoH client
// (browsers, systemd-resolved, curl) can use directly.
package wire

import (
	"encoding/base64"
	"fmt"

	"github.com/miekg/dns"
)

// ContentType is the media type RFC 8484 requires for DNS wire-format
// messages carried over HTTP.
const ContentType = "application/dns-message"

// Pack serializes a DNS message to wire format.
func Pack(m *dns.Msg) ([]byte, error) {
	b, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing DNS message: %w", err)
	}
	return b, nil
}

// Unpack parses wire-format bytes into a DNS message.
func Unpack(b []byte) (*dns.Msg, error) {
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return nil, fmt.Errorf("unpacking DNS message: %w", err)
	}
	return m, nil
}

// B64URLEncode encodes wire-format bytes using unpadded base64url, as used
// by the RFC 8484 GET "?dns=" parameter.
func B64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// B64URLDecode decodes an RFC 8484 "?dns=" parameter back to wire bytes.
func B64URLDecode(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decoding base64url dns parameter: %w", err)
	}
	return b, nil
}

// MinTTL returns the smallest TTL among a message's answer records, or ok=false
// if there are none (e.g. NXDOMAIN). Callers use this to decide how long an
// answer may be cached.
func MinTTL(m *dns.Msg) (ttl uint32, ok bool) {
	for i, rr := range m.Answer {
		if i == 0 || rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
		ok = true
	}
	return ttl, ok
}
