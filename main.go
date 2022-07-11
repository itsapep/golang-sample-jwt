package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/itsapep/golang-sample-jwt/config"
	"github.com/itsapep/golang-sample-jwt/delivery/middleware"
	"github.com/itsapep/golang-sample-jwt/model"
	"github.com/itsapep/golang-sample-jwt/utils"
)

var ApplicationName = "ENIGMA"
var JwtSigningMethod = jwt.SigningMethodHS256
var JwtSignatureKey = []byte("P@ssw0rd")

func main() {
	routerEngine := gin.Default()

	// routerEngine.Use(AuthTokenMiddleware()) //global middleware
	cfg := config.NewConfig()
	tokenService := utils.NewTokenService(cfg.TokenConfig)
	routerGroup := routerEngine.Group("/api")
	routerGroup.POST("/auth/login", func(ctx *gin.Context) {
		var user model.Credential
		if err := ctx.BindJSON(&user); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"message": "can't bind struct",
			})
			return
		}
		if user.Username == "enigma" && user.Password == "123" {
			token, err := tokenService.CreateAccessToken(&user)
			if err != nil {
				ctx.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			err = tokenService.StoreAccessToken(user.Username, token)
			if err != nil {
				ctx.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			ctx.JSON(http.StatusOK, gin.H{
				"token": token,
			})
		} else {
			ctx.AbortWithStatus(http.StatusUnauthorized)
		}
	})

	protectedGroup := routerGroup.Group("/master", middleware.NewTokenValidator(tokenService).RequireToken())
	protectedGroup.GET("/customer", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": ctx.GetString("user-id"),
		})
	})
	protectedGroup.GET("/product", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": ctx.GetString("user-id"),
		})
	})

	err := routerEngine.Run("localhost:8888")
	if err != nil {
		panic(err)
	}
}
