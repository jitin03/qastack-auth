package service

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/jitin07/qastackauth/domain"
	"github.com/jitin07/qastackauth/dto"
	"github.com/jitin07/qastackauth/errs"
	"github.com/jitin07/qastackauth/logger"
)

type UserService interface {
	GetAllUser()([]dto.UsersResponse,*errs.AppError)
	AddUser(request dto.UsersRegisterRequest) (*dto.NewUserRegisterResponse, *errs.AppError)
	Login(dto.LoginRequest) (*string, *errs.AppError)
		Verify(urlParams map[string]string) *errs.AppError
	GetUserByUsername(string) (*dto.UsersResponse,*errs.AppError)
}


type DefaultUserService struct {
	repo domain.UsersRepository
	rolePermissions domain.RolePermissions
}


func jwtTokenFromString(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.SIGNKEY), nil
	})
	if err != nil {
		logger.Error("Error while parsing token: " + err.Error())
		return nil, err
	}
	return token, nil
}
func (s DefaultUserService) Verify(urlParams map[string]string) *errs.AppError {
	// convert the string token to JWT struct
	if jwtToken, err := jwtTokenFromString(urlParams["token"]); err != nil {
		return errs.NewAuthorizationError(err.Error())
	} else {

		fmt.Println("token parsed",jwtToken)
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
			isAuthorized := s.rolePermissions.IsAuthorizedFor(claims.Role, urlParams["routeName"])
			if !isAuthorized {
				return errs.NewAuthorizationError(fmt.Sprintf("%s role is not authorized", claims.Role))
			}
			return nil
		} else {
			return errs.NewAuthorizationError("Invalid token")
		}
	}
}
func (s DefaultUserService) Login(req dto.LoginRequest) (*string, *errs.AppError) {

	login, err := s.repo.FindBy(req.Username, req.Password)
	if err != nil {
		return nil, err
	}

	token, err := login.GenerateToken()
	if  err != nil {
		return nil, err
	}

	return token,nil

}

func (s DefaultUserService)AddUser(request dto.UsersRegisterRequest)(*dto.NewUserRegisterResponse, *errs.AppError){
	
	u :=domain.Users{

		Username:   request.Username,
		Password:   request.Password,
		Email:      request.Email,
		Role:       request.Role,

	}

	if newUser, err := s.repo.AddUser(u); err != nil {
		return nil, err
	} else {
		return newUser.ToNewUserResponseDto(), nil
	}
}

func (s DefaultUserService) GetAllUser()([]dto.UsersResponse,*errs.AppError)  {
	users,err := s.repo.GetAllUser()
	if err != nil {
		return nil, err
	}
	response := make([]dto.UsersResponse, 0)
	for _, users := range users {
		response = append(response, users.ToDto())
	}
	return response, err

}

func (s DefaultUserService) GetUserByUsername(username string) (*dto.UsersResponse,*errs.AppError) {
	user,err := s.repo.GetUserByUsername(username)

	if err !=nil{
		return nil, err
	}
	response :=user.ToDto()


	return &response, nil
}

func NewUserService(repository domain.UsersRepository,permissions domain.RolePermissions) DefaultUserService {
	return DefaultUserService{repository,permissions}
}