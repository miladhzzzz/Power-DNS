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
	server.Handler = &DnsHandler{sshConn: "", dohServer: dohServer}

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

type DnsHandler struct {
	sshConn   string
	dohServer string
}

func(h *DnsHandler) HttpQuery(domain string) (*dns.Msg, error) {
	h.dohServer = dohServer

	q := new(dns.Msg)
    q.SetQuestion(dns.Fqdn(domain), dns.TypeA) // Adjust the type as per your requirement
    
	resp, err :=  h.forwardDNSRequest(q)

    if err != nil {
        return nil, err
    }

    return resp, nil
	
}

func (h *DnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
    var (
        resp *dns.Msg
        err  error
    )

    // Forward DNS request through SSH tunnel to DoH server
    resp, err = h.forwardDNSRequest(r)
    if err != nil {
        log.Printf("Failed to forward DNS request over HTTPS: %v", err)
        
        // If forwarding using DoH failed, try forwarding using plain method
        presp, err := h.forwardDNSPlain(r)
        if err != nil {
            log.Printf("Failed to forward DNS request over UDP to 8.8.8.8: %v", err)
            // Respond to the client with an error message or handle it according to your needs
            return
        }

        // Write DNS response back to client using plain method
        if err := w.WriteMsg(presp); err != nil {
            log.Printf("Failed to write DNS response: %v", err)
            // Handle the error accordingly
            return
        }

        log.Printf("Forwarded DNS request using plain method: %v", r.String())
        return
    }

    // Write DNS response back to client using DoH
    if err := w.WriteMsg(resp); err != nil {
        log.Printf("Failed to write DNS response: %v", err)
        // Handle the error accordingly
        return
    }

    log.Printf("Forwarded DNS request to DoH: %v", r.String())
}

func (h *DnsHandler) forwardDNSPlain(req *dns.Msg) (*dns.Msg, error) {
	
	// Create a new DNS client
    client := &dns.Client{}

    // Send the request to the other DNS server
    resp, _, err := client.Exchange(req, "8.8.8.8:53")
    if err!= nil {
        return nil, err
    }

    return resp, nil
}

func (h *DnsHandler) forwardDNSRequest(req *dns.Msg) (*dns.Msg, error) {
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
