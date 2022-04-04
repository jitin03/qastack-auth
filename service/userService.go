package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jitin07/qastackauth/domain"
	"github.com/jitin07/qastackauth/dto"
	"github.com/jitin07/qastackauth/errs"
	"github.com/jitin07/qastackauth/logger"
	"github.com/jitin07/qastackauth/utils"
	"github.com/labstack/gommon/log"
)

const dbTSLayout = "2006-01-02 15:04:05"

type UserService interface {
	GetAllUser() ([]dto.UsersResponse, *errs.AppError)
	AddUser(request dto.UsersRegisterRequest) (*dto.NewUserRegisterResponse, *errs.AppError)
	Login(dto.LoginRequest) (*dto.LoginResponse, *errs.AppError)
	Verify(urlParams map[string]string) *errs.AppError
	GetUserByUsername(string) (*dto.UsersResponse, *errs.AppError)
	Refresh(request dto.RefreshTokenRequest) (*dto.LoginResponse, *errs.AppError)
	StoreVerificationData(ctx context.Context, verificationData *domain.VerificationData) *errs.AppError
	GetVerificationData(ctx context.Context, email string, verificationDataType *domain.VerificationDataType) (*domain.VerificationData, error)
	DeleteVerificationData(ctx context.Context, email string, verificationDataType domain.VerificationDataType) error
	UpdateUserVerificationStatus(ctx context.Context, email string, status bool) error
	GetUserByID(ctx context.Context, userID string) (*domain.Users, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.Users, error)
	UpdatePassword(ctx context.Context, email string, password string, tokenHash string) error
	GetVerificationDataPasswordReset(ctx context.Context, email string, codetype int) (*domain.VerificationData, error)
	GetVerificationDataUserInvite(ctx context.Context, email string) (*domain.VerificationData, error)
}

type DefaultUserService struct {
	repo domain.UsersRepository
}

func jwtTokenFromString(tokenString string) (*jwt.Token, error) {
	log.Info(tokenString)
	token, err := jwt.ParseWithClaims(tokenString, &domain.AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HMAC_SAMPLE_SECRET), nil
	})
	if err != nil {
		logger.Error("Error while parsing token: " + err.Error())
		return nil, err
	}
	return token, nil
}
func (s DefaultUserService) GetUserByID(ctx context.Context, userID string) (*domain.Users, error) {
	user, appErr := s.repo.GetUserByID(ctx, userID)
	if appErr != nil {
		// log.Info("unable to get user to generate secret code for password reset" + appErr)

		return nil, appErr
	}
	return user, nil
}

func (s DefaultUserService) GetUserByEmail(ctx context.Context, email string) (*domain.Users, error) {
	user, appErr := s.repo.GetUserByEmail(ctx, email)
	if appErr != nil {
		// log.Info("unable to get user to generate secret code for password reset" + appErr)

		return nil, appErr
	}
	return user, nil
}
func (s DefaultUserService) UpdatePassword(ctx context.Context, email string, password string, tokenHash string) error {

	appError := s.repo.UpdatePassword(ctx, email, password, tokenHash)
	if appError != nil {
		return appError
	}

	return nil
}
func (s DefaultUserService) StoreVerificationData(ctx context.Context, verificationData *domain.VerificationData) *errs.AppError {

	appError := s.repo.StoreVerificationData(ctx, verificationData)
	if appError != nil {
		return errs.NewUnexpectedError("unable to store mail verification data")
	}

	return nil

}

func (s DefaultUserService) UpdateUserVerificationStatus(ctx context.Context, email string, status bool) error {

	appError := s.repo.UpdateUserVerificationStatus(ctx, email, status)
	if appError != nil {
		return appError
	}

	return nil

}

func (s DefaultUserService) DeleteVerificationData(ctx context.Context, email string, verificationDataType domain.VerificationDataType) error {
	appError := s.repo.DeleteVerificationData(ctx, email, verificationDataType)
	if appError != nil {
		return appError
	}

	return nil
}

func (s DefaultUserService) GetVerificationData(ctx context.Context, email string, verificationDataType *domain.VerificationDataType) (*domain.VerificationData, error) {
	actualVerificationData, appError := s.repo.GetVerificationData(ctx, email, verificationDataType)
	if appError != nil {

		return nil, appError
	}
	return actualVerificationData, nil
}

func (s DefaultUserService) GetVerificationDataPasswordReset(ctx context.Context, email string, codeType int) (*domain.VerificationData, error) {
	actualVerificationData, appError := s.repo.GetVerificationDataPasswordReset(ctx, email, codeType)
	if appError != nil {

		return nil, appError
	}
	return actualVerificationData, nil
}

func (s DefaultUserService) GetVerificationDataUserInvite(ctx context.Context, email string) (*domain.VerificationData, error) {
	actualVerificationData, appError := s.repo.GetVerificationDataUserInvite(ctx, email)
	if appError != nil {

		return nil, appError
	}
	return actualVerificationData, nil
}
func (s DefaultUserService) Refresh(request dto.RefreshTokenRequest) (*dto.LoginResponse, *errs.AppError) {
	if vErr := request.IsAccessTokenValid(); vErr != nil {
		if vErr.Errors == jwt.ValidationErrorExpired {
			// continue with the refresh token functionality
			var appErr *errs.AppError
			if appErr = s.repo.RefreshTokenExists(request.RefreshToken); appErr != nil {
				return nil, appErr
			}
			// generate a access token from refresh token.
			var accessToken string
			if accessToken, appErr = domain.NewAccessTokenFromRefreshToken(request.RefreshToken); appErr != nil {
				return nil, appErr
			}
			return &dto.LoginResponse{AccessToken: accessToken}, nil
		}
		return nil, errs.NewAuthenticationError("invalid token")
	}
	return nil, errs.NewAuthenticationError("cannot generate a new access token until the current one expires")
}

func (s DefaultUserService) Verify(urlParams map[string]string) *errs.AppError {
	var routeError *errs.AppError
	var routes *domain.RolePermission
	// convert the string token to JWT struct
	if jwtToken, err := jwtTokenFromString(urlParams["token"]); err != nil {
		return errs.NewAuthorizationError(err.Error())
	} else {

		fmt.Println("token parsed", jwtToken)
		/*
		   Checking the validity of the token, this verifies the expiry
		   time and the signature of the token
		*/
		if jwtToken.Valid {
			// type cast the token claims to jwt.MapClaims
			claims := jwtToken.Claims.(*domain.AccessTokenClaims)
			/* if Role if user then check if the account_id and customer_id
			   coming in the URL belongs to the same token
			*/
			if claims.IsUserRole() {
				if !claims.IsRequestVerifiedWithTokenClaims(urlParams) {
					return errs.NewAuthorizationError("request not verified with the token claims")
				}
			}
			// verify of the role is authorized to use the route
			// urlParams["routeName"]
			log.Info(claims.Role)
			log.Info(claims.Email)
			if routes, routeError = s.repo.GetAuthorisedRoutes(claims.Role, claims.Email); err != nil {
				return routeError
			}

			var route []string
			response := routes.ToAllRoutesDto()
			var isAuthorised bool
			// log.Info(response.Routes.String())

			json.Unmarshal([]byte(response.Routes.String()), &route)

			log.Info(route)
			for _, r := range route {

				if r == strings.TrimSpace(urlParams["routeName"]) {
					log.Info("Permission granted")
					isAuthorised = true
				}
			}

			log.Info(isAuthorised)
			if !isAuthorised {
				return errs.NewAuthorizationError(fmt.Sprintf("%s role is not authorized", claims.Role))
			}
			return nil
		} else {
			return errs.NewAuthorizationError("Invalid token")
		}
	}
}
func (s DefaultUserService) Login(req dto.LoginRequest) (*dto.LoginResponse, *errs.AppError) {
	var appErr *errs.AppError
	var login *domain.Login

	if login, appErr = s.repo.FindBy(req.Emailaddress, req.Password); appErr != nil {
		return nil, appErr
	}

	fmt.Println(login)
	if !login.IsVerified {
		logger.Error("unverified user")
		return nil, errs.NewAuthorizationError("unverified user")

	}

	claims := login.ClaimsForAccessToken()

	authToken := domain.NewAuthToken(claims)

	var accessToken, refreshToken string
	if accessToken, appErr = authToken.NewAccessToken(); appErr != nil {
		return nil, appErr
	}
	if refreshToken, appErr = s.repo.GenerateAndSaveRefreshTokenToStore(authToken); appErr != nil {
		return nil, appErr
	}
	// token, err := login.GenerateToken()
	// if err != nil {
	// 	return nil, err
	// }

	return &dto.LoginResponse{AccessToken: accessToken, RefreshToken: refreshToken}, nil

}

func (s DefaultUserService) AddUser(request dto.UsersRegisterRequest) (*dto.NewUserRegisterResponse, *errs.AppError) {

	u := domain.Users{

		Username:  request.Username,
		Password:  request.Password,
		Email:     request.Email,
		Role:      request.Role,
		CreatedAt: time.Now().Format(dbTSLayout),
		UpdatedAt: time.Now().Format(dbTSLayout),
		TokenHash: utils.GenerateUUID(),
	}

	if newUser, err := s.repo.AddUser(u); err != nil {
		return nil, err
	} else {
		return newUser.ToNewUserResponseDto(), nil
	}
}

func (s DefaultUserService) GetAllUser() ([]dto.UsersResponse, *errs.AppError) {
	users, err := s.repo.GetAllUser()
	if err != nil {
		return nil, err
	}
	response := make([]dto.UsersResponse, 0)
	for _, users := range users {
		response = append(response, users.ToDto())
	}
	return response, err

}

func (s DefaultUserService) GetUserByUsername(username string) (*dto.UsersResponse, *errs.AppError) {
	user, err := s.repo.GetUserByUsername(username)

	if err != nil {
		return nil, err
	}
	response := user.ToDto()

	return &response, nil
}

func NewUserService(repository domain.UsersRepository) DefaultUserService {
	return DefaultUserService{repository}
}
