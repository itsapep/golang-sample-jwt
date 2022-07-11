package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/itsapep/golang-sample-jwt/utils"
)

type AuthTokenMiddleware interface {
	RequireToken() gin.HandlerFunc
}

type authHeader struct {
	AuthorizationHeader string `header:"Authorization"`
}

type authTokenMiddleware struct {
	acctToken utils.Token
}

// RequireToken implements AuthTokenMiddleware
func (a *authTokenMiddleware) RequireToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := authHeader{}
		if err := c.ShouldBindHeader(&h); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
			c.Abort()
		}
		tokenString := strings.Replace(h.AuthorizationHeader, "Bearer ", "", -1)
		fmt.Println("tokenString: ", tokenString)
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}
		token, err := a.acctToken.VerifyAccessToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}
		fmt.Println("token: ", token)
		if token != nil {
			c.Next()
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}
	}
}

func NewTokenValidator(acctToken utils.Token) AuthTokenMiddleware {
	return &authTokenMiddleware{
		acctToken: acctToken,
	}
}
