package dns

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

var (
	localPort = 53 // local port DNS server listening on

	relayServer = "https://hans-army-version-raise.trycloudflare.com/dns/Query/" // relayServer address of the relay server you ran

	dohServer = "https://dns.google/dns-query" // DoHServer google public DoHServer
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

func (h *DnsHandler) HttpQuery(domain string) (*dns.Msg, error) {
	h.dohServer = relayServer

	// q := new(dns.Msg)
	// q.SetQuestion(dns.Fqdn(domain), dns.TypeA) // Adjust the type as per your requirement

	resp, err := h.httpDNSrelay(domain)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (h *DnsHandler) HttpRelay(domain string) (*dns.Msg, error) {
	h.dohServer = dohServer

	resp, err := h.forwardDNSOverHttps(domain)
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
	domain := r.Question[0].Name
	fmt.Printf("domain : %v", domain)
	// Forward DNS request through SSH tunnel to DoH server
	resp, err = h.localDNSrelay(r.Question[0].Name, r)
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
			log.Printf("Failed to write DNS response from failed condition: %v", err)
			// Handle the error accordingly
			return
		}

		log.Printf("Forwarded DNS request using plain method: %v", r.String())
		return
	}

	fmt.Printf("heres the response : %v", resp)
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
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (h *DnsHandler) localDNSrelay(req string, reqMsg *dns.Msg) (*dns.Msg, error) {
	// Create HTTP client for our relay server
	client := &http.Client{}

	q := relayServer + req

	resp, err := client.Get(q)
	if err != nil {
		return nil, fmt.Errorf("cannot reach relay server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non-successful response from relay server: %s", resp.Status)
	}

	// Decode JSON response
	var jsonResponse struct {
		Domain   string `json:"domain"`
		Response struct {
			Additional interface{} `json:"additional"`
			Answer     []struct {
				Hdr struct {
					Name     string `json:"Name"`
					Rrtype   uint16 `json:"Rrtype"`
					Class    uint16 `json:"Class"`
					Ttl      uint32 `json:"Ttl"`
					Rdlength uint16 `json:"Rdlength"`
				} `json:"Hdr"`
				A string `json:"A"`
			} `json:"answer"`
			Authority interface{} `json:"authority"`
			Question  []struct {
				Name   string `json:"Name"`
				Qtype  uint16 `json:"Qtype"`
				Qclass uint16 `json:"Qclass"`
			} `json:"question"`
		} `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jsonResponse); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %v", err)
	}

	// Extract DNS response
	if len(jsonResponse.Response.Answer) == 0 {
		return nil, fmt.Errorf("no answer found in JSON response")
	}

	// Create a new DNS message with the same ID as the request message
	respMsg := new(dns.Msg)
	respMsg.SetReply(reqMsg)
	respMsg.Compress = false // Ensure compression is turned off

	// Set the answer section of the response message
	for _, ans := range jsonResponse.Response.Answer {
		ip := net.ParseIP(ans.A)
		if ip != nil {
			domain := jsonResponse.Domain
			if !strings.HasSuffix(domain, ".") {
				domain += "."
			}
			a := &dns.A{
				Hdr: dns.RR_Header{
					Name:   domain,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    ans.Hdr.Ttl,
				},
				A: ip,
			}
			respMsg.Answer = append(respMsg.Answer, a)
		}
	}

	return respMsg, nil
}

func (h *DnsHandler) httpDNSrelay(req string) (*dns.Msg, error) {
	// Create HTTP client for our relay server
	client := &http.Client{}

	q := h.dohServer + req

	resp, err := client.Get(q)
	if err != nil {
		return nil, fmt.Errorf("cannot reach relay server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non-successful response from relay server: %s", resp.Status)
	}
	// Decode JSON response
	var jsonResponse struct {
		Domain   string `json:"domain"`
		Response struct {
			Additional interface{} `json:"additional"`
			Answer     []struct {
				Hdr struct {
					Name     string `json:"Name"`
					Rrtype   uint16 `json:"Rrtype"`
					Class    uint16 `json:"Class"`
					Ttl      uint32 `json:"Ttl"`
					Rdlength uint16 `json:"Rdlength"`
				} `json:"Hdr"`
				A string `json:"A"`
			} `json:"answer"`
			Authority interface{} `json:"authority"`
			Question  []struct {
				Name   string `json:"Name"`
				Qtype  uint16 `json:"Qtype"`
				Qclass uint16 `json:"Qclass"`
			} `json:"question"`
		} `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jsonResponse); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %v", err)
	}

	// Extract DNS response
	if len(jsonResponse.Response.Answer) == 0 {
		return nil, fmt.Errorf("no answer found in JSON response")
	}

	// Create a new DNS message
	respMsg := new(dns.Msg)
	for _, ans := range jsonResponse.Response.Answer {
		ip := net.ParseIP(ans.A)
		if ip != nil {
			domain := jsonResponse.Domain
			if !strings.HasSuffix(domain, ".") {
				domain += "."
			}
			a := &dns.A{
				Hdr: dns.RR_Header{
					Name:   domain,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    ans.Hdr.Ttl,
				},
				A: ip,
			}
			respMsg.Answer = append(respMsg.Answer, a)
		}
	}

	return respMsg, nil
}

func (h *DnsHandler) forwardDNSOverHttps(req string) (*dns.Msg, error) {
	// Create HTTP client for DoH server
	client := &http.Client{}
	domain := req + "."
	// Create DNS message
	dnsMsg := new(dns.Msg)
	dnsMsg.SetQuestion(domain, dns.TypeA) // Assuming it's an A record query

	// Encode DNS request to wire format
	reqData, err := dnsMsg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to encode DNS request: %w", err)
	}

	// Encode DNS wire format to base64url
	encodedReq := base64.RawURLEncoding.EncodeToString(reqData)

	// Construct JSON object with DNS query
	jsonReq := fmt.Sprintf(`{"dns":"%s"}`, encodedReq)

	// Send DNS request to DoH server
	resp, err := client.Post(h.dohServer, "application/dns-message", strings.NewReader(jsonReq))
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

