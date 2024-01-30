package dns

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/miekg/dns"
)

var (
	localPort = 5335 // local port DNS server listening

	dohServer = "https://dns.google/dns-query"
)

func StartDNSserver() {
	server := &dns.Server{Addr: fmt.Sprintf(":%d", localPort), Net: "udp"}
	server.Handler = &dnsHandler{sshConn: "", dohServer: dohServer}

	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Failed to Start DNS Server: %v", err)
		}
	}()
	defer server.Shutdown()

	log.Printf("DNS server listening on port %d", localPort)

	// wait indefinitely
	select {}
}

type dnsHandler struct {
	sshConn   string
	dohServer string
}

func (h *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	var (
		resp *dns.Msg
		err  error
	)

	// Forward DNS request through SSH tunnel to DoH server
	resp, err = h.forwardDNSRequest(r)
	if err != nil {
		log.Printf("Failed to forward DNS request: %v", err)
		return
	}

	log.Printf("Forwarded DNS Request to DOH: %v", r.String())

	// Write DNS response back to client
	if err := w.WriteMsg(resp); err != nil {
		log.Printf("Failed to write DNS response: %v", err)
	}
}

func (h *dnsHandler) forwardDNSRequest(req *dns.Msg) (*dns.Msg, error) {
	// Create HTTP client for DoH server
	client := &http.Client{}

	// Encode DNS request
	reqData, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to encode DNS request: %w", err)
	}

	// Send DNS request to DoH server
	resp, err := client.Post(h.dohServer, "application/dns-message", bytes.NewReader(reqData))
	if err != nil {
		return nil, fmt.Errorf("failed to send DNS request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Decode DNS response
	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(respBody); err != nil {
		return nil, fmt.Errorf("failed to decode DNS response: %w", err)
	}

	return respMsg, nil
}
