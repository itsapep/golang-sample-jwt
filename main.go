package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type AuthHeader struct {
	AuthorisationHeader string `header:"Authorisation"`
}

func main() {
	routerEngine := gin.Default()
	routerGroup := routerEngine.Group("/api")

	routerGroup.GET("/customer", func(ctx *gin.Context) {
		authHeader := AuthHeader{}
		err := ctx.ShouldBindHeader(&authHeader)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"message": "unauthorised",
			})
			return
		}

		if authHeader.AuthorisationHeader == "123456" {
			ctx.JSON(http.StatusOK, gin.H{
				"message": "PONG",
			})
			return
		}

		ctx.JSON(http.StatusUnauthorized, gin.H{
			"message": "invalid",
		})
	})

	routerGroup.GET("/product", func(ctx *gin.Context) {
		authHeader := AuthHeader{}
		err := ctx.ShouldBindHeader(&authHeader)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"message": "unauthorised",
			})
			return
		}

		if authHeader.AuthorisationHeader == "123456" {
			ctx.JSON(http.StatusOK, gin.H{
				"message": "PONG",
			})
			return
		}

		ctx.JSON(http.StatusUnauthorized, gin.H{
			"message": "invalid",
		})
	})

	err := routerEngine.Run(":8888")
	if err != nil {
		panic(err)
	}
}
