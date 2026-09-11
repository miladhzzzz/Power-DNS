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
	"testing"
	"time"

	"github.com/miekg/dns"
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
