package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/miladhzzzz/power-dns/internal/metrics"
)

// fakeUpstream answers every A query with a fixed IP, so the test doesn't
// depend on real network access.
type fakeUpstream struct{}

func (fakeUpstream) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeA {
		rr, _ := dns.NewRR(req.Question[0].Name + " 60 IN A 203.0.113.7")
		resp.Answer = append(resp.Answer, rr)
	}
	return resp, nil
}

// slowCountingUpstream records how many times it was actually invoked and
// sleeps before answering, so concurrent callers genuinely overlap in time
// -- what a real coalescing test needs, versus an instant fake that might
// finish before a second caller even checks whether a call is in flight.
type slowCountingUpstream struct {
	calls *int32
	delay time.Duration
}

func (u *slowCountingUpstream) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	atomic.AddInt32(u.calls, 1)
	time.Sleep(u.delay)
	resp := new(dns.Msg)
	resp.SetReply(req)
	rr, _ := dns.NewRR(req.Question[0].Name + " 60 IN A 198.51.100.42")
	resp.Answer = append(resp.Answer, rr)
	return resp, nil
}

func TestRelayCoalescesConcurrentIdenticalQueries(t *testing.T) {
	var calls int32
	up := &slowCountingUpstream{calls: &calls, delay: 50 * time.Millisecond}
	reg := metrics.New()

	srv := NewServer(up, nil, reg, "", nil, 0)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	const n = 20
	var wg sync.WaitGroup
	results := make([]*dns.Msg, n)
	reqs := make([]*dns.Msg, n)
	for i := 0; i < n; i++ {
		reqs[i] = new(dns.Msg)
		reqs[i].SetQuestion("coalesce.example.com.", dns.TypeA)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			client := NewClient(ts.URL, "", "", 2*time.Second)
			resp, err := client.Resolve(context.Background(), reqs[i])
			if err != nil {
				t.Errorf("caller %d: Resolve: %v", i, err)
				return
			}
			results[i] = resp
		}(i)
	}
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected exactly 1 real upstream call for %d concurrent identical queries, got %d", n, got)
	}
	for i, resp := range results {
		if resp == nil {
			continue // already reported via t.Errorf above
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("caller %d: expected 1 answer, got %d", i, len(resp.Answer))
		}
		if resp.Id != reqs[i].Id {
			t.Fatalf("caller %d: expected response Id %d to match its own request Id %d (coalescing must not leak another caller's Id)", i, resp.Id, reqs[i].Id)
		}
	}

	var b strings.Builder
	reg.WriteProm(&b)
	out := b.String()
	// A clean partition of all 20 callers: exactly 1 triggered the real
	// call, the other 19 rode along on it.
	if !strings.Contains(out, "powerdns_relay_calls_total 1") {
		t.Fatalf("expected exactly 1 relay call recorded, got:\n%s", out)
	}
	if !strings.Contains(out, "powerdns_relay_coalesced_total 19") {
		t.Fatalf("expected exactly 19 coalesced relay queries recorded, got:\n%s", out)
	}
}

func TestRelayClientServerRoundTripDoH(t *testing.T) {
	srv := NewServer(fakeUpstream{}, nil, nil, "", nil, 0)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	client := NewClient(ts.URL, "", "", 2*time.Second)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	resp, err := client.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	assertOneAnswer(t, resp)
}

func TestRelayRequiresAuthToken(t *testing.T) {
	srv := NewServer(fakeUpstream{}, nil, nil, "secret", nil, 0)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	// No token: should fail.
	client := NewClient(ts.URL, "", "", 2*time.Second)
	if _, err := client.Resolve(context.Background(), req); err == nil {
		t.Fatalf("expected request without token to be rejected")
	}

	// Correct token: should succeed.
	authedClient := NewClient(ts.URL, "", "secret", 2*time.Second)
	if _, err := authedClient.Resolve(context.Background(), req); err != nil {
		t.Fatalf("expected authed request to succeed, got %v", err)
	}
}

func TestRelayClientServerRoundTripDoT(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)

	base := NewServer(fakeUpstream{}, nil, nil, "", nil, 0)
	dotSrv := NewDoTServer(base, certFile, keyFile)

	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- dotSrv.Run(ctx, addr) }()
	waitForListener(t, addr)

	client := NewClient("", addr, "", 2*time.Second)
	// The relay's self-signed cert isn't in any trust store, so skip
	// verification for this test -- production deployments should use a
	// real certificate and leave verification on.
	client.DoTClient.TLSConfig.InsecureSkipVerify = true

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	resp, err := client.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("Resolve over DoT: %v", err)
	}
	assertOneAnswer(t, resp)

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("dot server stopped: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("dot server did not shut down in time")
	}
}

func assertOneAnswer(t *testing.T, resp *dns.Msg) {
	t.Helper()
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "203.0.113.7" {
		t.Fatalf("unexpected answer: %v", resp.Answer[0])
	}
}

// writeSelfSignedCert generates a throwaway EC certificate valid for
// "localhost" and writes it to two temp files, for exercising the DoT
// listener without needing a real CA-signed certificate in tests.
func writeSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("creating cert file: %v", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encoding cert: %v", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	keyOut, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("creating key file: %v", err)
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("encoding key: %v", err)
	}

	return certFile, keyFile
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding free port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("dot server never started listening on %s", addr)
}
