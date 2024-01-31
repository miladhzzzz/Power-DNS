package api

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"github.com/miladhzzzz/power-dns/internal/api/controllers"
	"github.com/miladhzzzz/power-dns/internal/api/routes"
)

var (
	DNSController      controllers.DNSController
	DNSRouteController routes.DNSRouteController

	server *gin.Engine
)

func init() {
	DNSController = controllers.NewDNSController()
	DNSRouteController = routes.NewDNSRouteController(DNSController)

	logFile, _ := os.Create("DNS-HTTP.log")

	server = gin.Default()

	server.Use(gin.LoggerWithWriter(logFile))
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

	log.Fatal(server.Run(":8000"))
}
