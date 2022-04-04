package domain

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jitin07/qastackauth/errs"
	"github.com/jitin07/qastackauth/logger"
)

const SIGNKEY string = "kdnjsndjnd*jdnj212md"

type Login struct {
	Username   string `db:"username"`
	Role       string `db:"role"`
	Email      string `db:"email"`
	IsVerified bool   `db:"isverified"`
}

func (l Login) GenerateToken() (*string, *errs.AppError) {

	claims := l.ClaimsForAccessToken()

	logger.Info(fmt.Sprintf("Claims is %s", claims))

	// token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	authToken := NewAuthToken(claims)
	accessToken, appErr := authToken.NewAccessToken()

	if appErr != nil {
		// appErr.Error("Failed while signing the token " + err.Error())
		return nil, appErr
	}

	// signedTokenAsString, err := token.SignedString([]byte(SIGNKEY))

	// if err != nil {
	// 	logger.Error("Failed while signing the token " + err.Error())
	// 	return nil, errs.NewUnexpectedError("Cannot generate token")
	// }
	return &accessToken, nil
}

func (l Login) ClaimsForAccessToken() AccessTokenClaims {
	if l.Role == "User" {
		return l.claimsForUser()
	} else {
		return l.claimsForAdmin()
	}
}

func (l Login) claimsForUser() AccessTokenClaims {
	//projects := strings.Split(l.Project_id.String, ",")
	return AccessTokenClaims{

		Username: l.Username,
		Role:     l.Role,
		Email:    l.Email,

		StandardClaims: jwt.StandardClaims{

			ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION).Unix(),
		},
	}
}

func (l Login) claimsForAdmin() AccessTokenClaims {
	return AccessTokenClaims{
		Username: l.Username,
		Role:     l.Role,
		Email:    l.Email,
		StandardClaims: jwt.StandardClaims{

			ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION).Unix(),
		},
	}
}
