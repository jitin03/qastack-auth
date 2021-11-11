package domain

import (
	"github.com/dgrijalva/jwt-go"
	"time"
)

const HMAC_SAMPLE_SECRET = "hmacSampleSecret"

const REFRESH_TOKEN_DURATION = time.Hour * 24 * 30

type RefreshTokenClaims struct {
	TokenType  string   `json:"token_type"`

	Username   string   `json:"un"`
	Role       string   `json:"role"`
	jwt.StandardClaims
}

type AccessTokenClaims struct {

	Username   string   `json:"username"`
	Role       string   `json:"role"`
	jwt.StandardClaims
}

func (u AccessTokenClaims) IsUserRole() bool {
	return u.Role == "user"
}

//func (u AccessTokenClaims) IsValidCustomerId(customerId string) bool {
//	return u.CustomerId == customerId
//}
//
//func (c AccessTokenClaims) IsValidAccountId(accountId string) bool {
//	if accountId != "" {
//		accountFound := false
//		for _, a := range c.Accounts {
//			if a == accountId {
//				accountFound = true
//				break
//			}
//		}
//		return accountFound
//	}
//	return true
//}

func (c AccessTokenClaims) IsRequestVerifiedWithTokenClaims(urlParams map[string]string) bool {
	//if c.CustomerId != urlParams["customer_id"] {
	//	return false
	//}
	//
	//if !c.IsValidAccountId(urlParams["account_id"]) {
	//	return false
	//}
	return true
}

func (c AccessTokenClaims) RefreshTokenClaims() RefreshTokenClaims {
	return RefreshTokenClaims{
		TokenType:  "refresh_token",

		Username:   c.Username,
		Role:       c.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(REFRESH_TOKEN_DURATION).Unix(),
		},
	}
}

func (c RefreshTokenClaims) AccessTokenClaims() AccessTokenClaims {
	return AccessTokenClaims{

		Username:   c.Username,
		Role:       c.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION).Unix(),
		},
	}
}
