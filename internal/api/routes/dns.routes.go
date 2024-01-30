package routes

//
//import (
//	"github.com/gin-gonic/gin"
//
//	"github.com/miladhzzzz/power-dns/internal/api/controllers"
//)
//
//var (
//	ctx *gin.Context
//)
//
//type DNSRouteController struct {
//	dnsController controllers.dnsController
//}
//
//func NewDNSRouteController(authController controllers.AuthController) DNSRouteController {
//	return AuthRouteController{authController}
//}
//
//func (rc *DNSRouteController) DNSRoute(rg *gin.RouterGroup) {
//	router := rg.Group("/dns")
//
//	router.GET("/login", rc.authController.LoginHandler())
//	router.POST("/cli", rc.authController.Cli())
//
//	private := router.Group("")
//
//	private.Use(rc.authController.Auth())
//
//	private.GET("/", func(context *gin.Context) {
//
//	})
//
//}
