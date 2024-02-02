package controllers

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/miladhzzzz/power-dns/internal/dns"
)

type DNSController struct {
	dnsHandler *dns.DnsHandler
	ctx        context.Context
}

func NewDNSController(dnsHandler *dns.DnsHandler) DNSController {
	return DNSController{ctx: context.TODO(), dnsHandler: dnsHandler}
}

func (dc *DNSController) Query() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		query := ctx.Param("query")

		if query == "" {
			log.Print("no query received")
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "No query received"})
			return
		}

		resp, err := dc.dnsHandler.HttpQuery(query)
		if err != nil {
			log.Printf("couldn't make the request: %v", err)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Serialize the DNS response to JSON
		dnsResponse := make(map[string]interface{})
		dnsResponse["question"] = resp.Question
		dnsResponse["answer"] = resp.Answer
		dnsResponse["authority"] = resp.Ns
		dnsResponse["additional"] = resp.Extra

		// Send the response back
		ctx.JSON(http.StatusOK, gin.H{"domain": query, "response": dnsResponse})

		// Log the query
		log.Printf("got a query: %v", query)
	}
}

func (dc *DNSController) Relay() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		query := ctx.Param("query")

		if query == "" {
			log.Print("no query received")
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "no query received"})
			return
		}

		resp, err := dc.dnsHandler.HttpRelay(query)
		if err != nil {
			log.Printf("Couldnt make the request: %v", err)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Serialize the DNS response to JSON
		dnsResponse := make(map[string]interface{})
		dnsResponse["question"] = resp.Question
		dnsResponse["answer"] = resp.Answer
		dnsResponse["authority"] = resp.Ns
		dnsResponse["additional"] = resp.Extra

		// Send the response back
		ctx.JSON(http.StatusOK, gin.H{"domain": query, "response": dnsResponse})

		// Log the query
		log.Printf("relay got a query: %v", query)
	}
}
