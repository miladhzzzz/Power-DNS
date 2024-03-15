package api

import (
	"log"
	"net/http"
	"os"
	"fmt"
	"net"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"github.com/miladhzzzz/power-dns/internal/api/controllers"
	"github.com/miladhzzzz/power-dns/internal/api/routes"
	"github.com/miladhzzzz/power-dns/internal/dns"
)

var (
	DNSController      controllers.DNSController
	DNSRouteController routes.DNSRouteController

	server *gin.Engine
)

func init() {
    dnsHandler := &dns.DnsHandler{} // Initialize DnsHandler instance
	

    DNSController = controllers.NewDNSController(dnsHandler)
    DNSRouteController = routes.NewDNSRouteController(DNSController)
 
    logFile, _ := os.Create("DNS-HTTP.log")

    server = gin.Default()

    server.Use(gin.LoggerWithWriter(logFile))
}

func getContainerIP() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to get network interfaces: %v", err)
	}

	for _, iface := range interfaces {
		if iface.Name == "eth0" || iface.Name == "eth1" {
			addrs, err := iface.Addrs()
			if err != nil {
				return "", fmt.Errorf("failed to get addresses for interface %s: %v", iface.Name, err)
			}

			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
					return ipNet.IP.String(), nil
				}
			}
		}
	}

	return "", fmt.Errorf("IP address not found")
}

func StartGinAPI() {
	r := server.Group("")

	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{"http://localhost:8000"}
	corsConfig.AllowCredentials = true

	server.Use(cors.New(corsConfig))

	r.GET("/", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"message": "pong!"})
	})

	DNSRouteController.DNSRoute(r)

	container_ip, err := getContainerIP()

	if err != nil{
		fmt.Printf("did not find the container ip")
		log.Fatal(server.Run(":8000"))
	}

	log.Fatal(server.Run(container_ip + ":8000"))
}
