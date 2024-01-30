package main

import (
	"github.com/miladhzzzz/power-dns/internal/api"

	"github.com/miladhzzzz/power-dns/internal/dns"
	_ "github.com/miladhzzzz/power-dns/internal/k8s"
)

func main() {
	// Starting the DNS server
	go api.StartGinAPI()

	dns.StartDNSserver()
	// Starting Api server
}
