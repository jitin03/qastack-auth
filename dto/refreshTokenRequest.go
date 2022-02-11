package dto

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
	"github.com/jitin07/qastackauth/logger"
)

type RefreshTokenRequest struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (r RefreshTokenRequest) IsAccessTokenValid() *jwt.ValidationError {

	// 1. invalid token.
	// 2. valid token but expired
	_, err := jwt.Parse(r.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte("hmacSampleSecret"), nil
	})
	if err != nil {
		logger.Error("error while parsing token:" + err.Error())
		var vErr *jwt.ValidationError
		if errors.As(err, &vErr) {
			return vErr
		}
	}
	return nil
}
