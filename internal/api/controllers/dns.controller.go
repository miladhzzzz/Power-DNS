package controllers

import (
	"context"
	"log"

	"github.com/gin-gonic/gin"
)

type DNSController struct {
	ctx context.Context
}

func NewDNSController() DNSController {
	return DNSController{ctx: context.TODO()}
}

func (dc *DNSController) Query() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		err, query := ctx.Get("Query")
		if err != nil {
			log.Print("no query recieved")
		}
		// this is the query over http localy available through api
		log.Printf("got a query : %v", query)
	}
}
