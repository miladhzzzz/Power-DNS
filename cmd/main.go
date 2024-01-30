package main

import (
	"fmt"
	"net"

	"github.com/miladhzzzz/power-dns/internal/api"

	"github.com/miekg/dns"
	_ "github.com/miladhzzzz/power-dns/internal/k8s"
)

// localPort = 5337
var vlessDoHEnabled bool

func main() {
	go api.StartGinAPI()

	dns.HandleFunc(".", handleDNSRequest)

	server := &dns.Server{Addr: ":5335", Net: "udp"}

	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("Error starting DNS server: %v\n", err)
	} else {
		fmt.Printf("DNS Server is listening at :5335 UDP...")
	}
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	fmt.Println("Received DNS request from:", w.RemoteAddr())

	msg := new(dns.Msg)
	msg.SetReply(r)

	// Check if Vless-DoH feature is enabled
	if vlessDoHEnabled {
		// Forward DNS queries to a public DoH server using Vless
		resp, err := vlessForwardDNSQuery(r)
		if err != nil {
			// Handle error
			fmt.Println(err)
		}
		msg = resp
	} else {
		// Implement custom DNS response logic here

		// Example: If the DNS query type is A, respond with a custom IP address
		if r.Question[0].Qtype == dns.TypeA {
			// Create a new A record with the desired IP address
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				A: net.ParseIP("192.168.1.1"),
			}

			// Add the A record to the DNS response message
			msg.Answer = append(msg.Answer, rr)
		}

		// Implement other custom DNS response logic based on the query type
	}

	// Write the DNS response message to the client
	_ = w.WriteMsg(msg)
}

func vlessForwardDNSQuery(r *dns.Msg) (*dns.Msg, error) {
	// Implement logic to forward DNS queries to a public DoH server using Vless
	// Example: Forward the DNS query to Google's public DoH server

	// Create a new DNS client
	client := dns.Client{}

	// Create a new DNS message for the DoH query
	dohMsg := &dns.Msg{}
	dohMsg.SetQuestion(r.Question[0].Name, r.Question[0].Qtype)

	// Send the DoH query to the public DoH server
	resp, _, err := client.Exchange(dohMsg, "https://dns.google/dns-query")
	if err != nil {
		return nil, err
	}

	return resp, nil
}
