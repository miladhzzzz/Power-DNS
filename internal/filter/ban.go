// Package filter implements answer-level bans used to reject poisoned or
// otherwise undesirable DNS responses before they are returned to clients
// or stored in the cache.
//
// The primary use today is rejecting Iranian GFI DNS-injection addresses
// (10.10.34.0/24 and related) that appear when plain UDP/53 traffic is
// intercepted. The same structure is intended to grow into ad-blocking and
// known-bad-domain exclusions without changing call sites.
package filter

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// BanList holds CIDR networks (and, later, domain patterns) that must never
// appear in a DNS answer we accept or cache.
type BanList struct {
	nets []*net.IPNet
}

// NewBanList parses a list of CIDR strings (e.g. "10.10.34.0/24"). Invalid
// entries are skipped and reported in the returned error string so a partial
// list still works.
func NewBanList(cidrs []string) (*BanList, error) {
	b := &BanList{}
	var errs []string
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, network, err := net.ParseCIDR(c)
		if err != nil {
			// Allow bare IPs as /32 or /128.
			if ip := net.ParseIP(c); ip != nil {
				if ip.To4() != nil {
					_, network, err = net.ParseCIDR(c + "/32")
				} else {
					_, network, err = net.ParseCIDR(c + "/128")
				}
			}
			if err != nil {
				errs = append(errs, fmt.Sprintf("%q: %v", c, err))
				continue
			}
		}
		b.nets = append(b.nets, network)
	}
	if len(errs) > 0 {
		return b, fmt.Errorf("some banned CIDRs failed to parse: %s", strings.Join(errs, "; "))
	}
	return b, nil
}

// Empty reports whether the list has no networks configured.
func (b *BanList) Empty() bool {
	return b == nil || len(b.nets) == 0
}

// ContainsIP reports whether ip falls in any banned network.
func (b *BanList) ContainsIP(ip net.IP) bool {
	if b == nil || ip == nil {
		return false
	}
	for _, n := range b.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ContainsAnswer scans Answer (and optionally Additional) RRs for A/AAAA
// records whose addresses fall in a banned network. Returns the first
// matching IP string, or "" if clean.
func (b *BanList) ContainsAnswer(msg *dns.Msg) string {
	if b == nil || b.Empty() || msg == nil {
		return ""
	}
	for _, rr := range msg.Answer {
		if ip := rrIP(rr); ip != nil && b.ContainsIP(ip) {
			return ip.String()
		}
	}
	// Also check Additional — some poison responses put the fake A there.
	for _, rr := range msg.Extra {
		if ip := rrIP(rr); ip != nil && b.ContainsIP(ip) {
			return ip.String()
		}
	}
	return ""
}

func rrIP(rr dns.RR) net.IP {
	switch v := rr.(type) {
	case *dns.A:
		return v.A
	case *dns.AAAA:
		return v.AAAA
	default:
		return nil
	}
}
