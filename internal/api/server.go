package api

import "github.com/gin-gonic/gin"

func StartGinAPI() {
	r := gin.Default()

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	r.Run(":8000")
}
