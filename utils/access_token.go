package utils

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/itsapep/golang-sample-jwt/config"
	"github.com/itsapep/golang-sample-jwt/model"
)

type Token interface {
	CreateAccessToken(cred *model.Credential) (string, error)
	VerifyAccessToken(tokenString string) (jwt.MapClaims, error)
}

type token struct {
	cfg config.TokenConfig
}

// CreateAccessToken implements Token
func (t *token) CreateAccessToken(cred *model.Credential) (string, error) {
	now := time.Now().UTC()
	end := now.Add(t.cfg.AccessTokenLifeTime)

	claims := MyClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer: t.cfg.ApplicationName,
		},
		Username: cred.Username,
		Email:    cred.Email,
	}
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = end.Unix()
	token := jwt.NewWithClaims(
		t.cfg.JwtSigningMethod,
		claims,
	)
	return token.SignedString([]byte(t.cfg.JwtSignatureKey))
}

// VerifyAccessToken implements Token
func (t *token) VerifyAccessToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("signing method invalid")
		} else if method != t.cfg.JwtSigningMethod {
			return nil, fmt.Errorf("signing method invalid")
		}

		return []byte(t.cfg.JwtSignatureKey), nil
	})
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, err
	}
	return claims, nil
}

func NewTokenService(cfg config.TokenConfig) Token {
	return &token{
		cfg: cfg,
	}
}
