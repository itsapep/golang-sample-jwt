package utils

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/itsapep/golang-sample-jwt/config"
	"github.com/itsapep/golang-sample-jwt/model"
)

type Token interface {
	CreateAccessToken(cred *model.Credential) (*model.TokenDetails, error)
	VerifyAccessToken(tokenString string) (*model.AccessDetails, error)
	StoreAccessToken(userName string, tokenDetail *model.TokenDetails) error
	FetchAccessToken(accessDetail *model.AccessDetails) (string, error)
}

type token struct {
	cfg config.TokenConfig
}

// CreateAccessToken implements Token
func (t *token) CreateAccessToken(cred *model.Credential) (*model.TokenDetails, error) {
	td := &model.TokenDetails{}
	now := time.Now().UTC()
	end := now.Add(t.cfg.AccessTokenLifeTime)

	td.AtExpires = end.Unix()
	td.AccessUUID = uuid.New().String()
	claims := MyClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer: t.cfg.ApplicationName,
		},
		Username:   cred.Username,
		Email:      cred.Email,
		AccessUUID: td.AccessUUID,
	}
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = end.Unix()
	token := jwt.NewWithClaims(
		t.cfg.JwtSigningMethod,
		claims,
	)
	newToken, err := token.SignedString([]byte(t.cfg.JwtSignatureKey))
	td.AccessToken = newToken
	if err != nil {
		return nil, err
	}
	return td, nil
}

// StoreAccessToken implements Token
func (t *token) StoreAccessToken(userName string, tokenDetail *model.TokenDetails) error {
	at := time.Unix(tokenDetail.AtExpires, 0)
	now := time.Now()
	err := t.cfg.Client.Set(context.Background(), tokenDetail.AccessUUID, userName, at.Sub(now)).Err()
	if err != nil {
		return err
	}
	return nil
}

// FetchAccessToken implements Token
func (t *token) FetchAccessToken(accessDetail *model.AccessDetails) (string, error) {
	if accessDetail != nil {
		userId, err := t.cfg.Client.Get(context.Background(), accessDetail.AccessUUID).Result()
		if err != nil {
			return "", err
		}
		return userId, nil
	} else {
		return "", errors.New("invalid access")
	}
}

// VerifyAccessToken implements Token
func (t *token) VerifyAccessToken(tokenString string) (*model.AccessDetails, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("signing method invalid")
		} else if method != t.cfg.JwtSigningMethod {
			return nil, fmt.Errorf("signing method invalid")
		}

		return []byte(t.cfg.JwtSignatureKey), nil
	})
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid || claims["iss"] != t.cfg.ApplicationName {
		log.Println("Token invalid ...")
		return nil, err
	}
	accessUUID := claims["AccessUUID"].(string)
	userName := claims["Username"].(string)
	return &model.AccessDetails{
		AccessUUID: accessUUID,
		Username:   userName,
	}, nil
}

func NewTokenService(cfg config.TokenConfig) Token {
	return &token{
		cfg: cfg,
	}
}
