package domain

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/jitin07/qastackauth/errs"
	"github.com/jitin07/qastackauth/logger"
	"time"
)

const ACCESS_TOKEN_DURATION = time.Hour
const SIGNKEY string="kdnjsndjnd*jdnj212md"
type Login struct {
	Username string `db:"username"`
	Role     string `db:"role"`
}

func (l Login) GenerateToken() (*string, *errs.AppError) {

	var claims jwt.MapClaims


	claims = l.claimsForAdmin()

	logger.Info(fmt.Sprintf("Claims is %s", claims))

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedTokenAsString, err := token.SignedString([]byte(SIGNKEY))

	if err != nil {
		logger.Error("Failed while signing the token " + err.Error())
		return nil, errs.NewUnexpectedError("Cannot generate token")
	}
	return &signedTokenAsString, nil
}

//
//func (l Login) ClaimsForAccessToken() AccessTokenClaims {
//	if l.Accounts.Valid && l.CustomerId.Valid {
//		return l.claimsForUser()
//	} else {
//		return l.claimsForAdmin()
//	}
//}
//
func (l Login) claimsForUser() jwt.MapClaims {
	//projects := strings.Split(l.Project_id.String, ",")
	return jwt.MapClaims{

		"Username": l.Username,
		"Role":     l.Role,

		"exp": time.Now().Add(ACCESS_TOKEN_DURATION).Unix(),
	}
}

func (l Login) claimsForAdmin() jwt.MapClaims {
	return jwt.MapClaims{
		"Username": l.Username,
		"Role":     l.Role,
		"exp":      time.Now().Add(ACCESS_TOKEN_DURATION).Unix(),
	}
}
