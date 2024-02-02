package routes

import (
	"github.com/gin-gonic/gin"

	"github.com/miladhzzzz/power-dns/internal/api/controllers"
)

type DNSRouteController struct {
	dnsController controllers.DNSController
}

func NewDNSRouteController(DNSController controllers.DNSController) DNSRouteController {
	return DNSRouteController{DNSController}
}

func (dc *DNSRouteController) DNSRoute(rg *gin.RouterGroup) {
	router := rg.Group("/dns")

	router.GET("/Query/:query", dc.dnsController.Query())
	router.GET("/:query", dc.dnsController.Relay())

	// router.POST("/cli", rc.authController.Cli())
}
