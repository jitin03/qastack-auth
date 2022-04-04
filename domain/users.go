package domain

import (
	"context"
	"database/sql"
	"time"

	"github.com/jitin07/qastackauth/dto"
	"github.com/jitin07/qastackauth/errs"
	"github.com/jmoiron/sqlx/types"
)

type Users struct {
	User_Id    int            `db:"users_id"`
	Username   string         `db:"username"`
	Password   string         `db:"password"`
	Email      string         `db:"email"`
	Role       string         `db:"role"`
	TokenHash  string         `db:"tokenhash"`
	IsVerified bool           `db:"isverified"`
	CreatedAt  string         `db:"created_at"`
	UpdatedAt  string         `db:"updated_at"`
	Project_id sql.NullString `db:"project_id"`
}

func (user Users) ToDto() dto.UsersResponse {
	return dto.UsersResponse{
		User_Id:    user.User_Id,
		Username:   user.Username,
		Password:   user.Password,
		Email:      user.Email,
		Role:       user.Role,
		Project_id: user.Project_id,
	}
}

func (user Users) ToNewUserResponseDto() *dto.NewUserRegisterResponse {
	return &dto.NewUserRegisterResponse{user.User_Id}
}

func (t RolePermission) ToAllRoutesDto() AllRoutes {
	return AllRoutes{
		Routes: t.Routes,
	}
}

type AllRoutes struct {
	Routes types.JSONText `json:"routes"`
}

type UsersRepository interface {
	AddUser(user Users) (*Users, *errs.AppError)
	GetAuthorisedRoutes(role_name string, email string) (*RolePermission, *errs.AppError)
	GetUserByUsername(string) (*Users, *errs.AppError)
	GetAllUser() ([]Users, *errs.AppError)
	FindBy(username string, password string) (*Login, *errs.AppError)
	GenerateAndSaveRefreshTokenToStore(authToken AuthToken) (string, *errs.AppError)
	RefreshTokenExists(refreshToken string) *errs.AppError
	StoreVerificationData(ctx context.Context, verificationData *VerificationData) *errs.AppError
	GetVerificationData(ctx context.Context, email string, verificationDataType *VerificationDataType) (*VerificationData, error)
	GetVerificationDataPasswordReset(ctx context.Context, email string, codetype int) (*VerificationData, error)
	GetVerificationDataUserInvite(ctx context.Context, email string) (*VerificationData, error)
	UpdateUserVerificationStatus(ctx context.Context, email string, status bool) error
	DeleteVerificationData(ctx context.Context, email string, verificationDataType VerificationDataType) error
	GetUserByID(ctx context.Context, userID string) (*Users, error)
	GetUserByEmail(ctx context.Context, email string) (*Users, error)
	UpdatePassword(ctx context.Context, email string, password string, tokenHash string) error
}
type VerificationDataType int

const (
	MailConfirmation VerificationDataType = iota + 1
	PassReset
)

// VerificationData represents the type for the data stored for verification.
type VerificationData struct {
	Email     string               `json:"email" validate:"required" sql:"email"`
	Code      string               `json:"code" validate:"required" sql:"code"`
	ExpiresAt time.Time            `json:"expiresat" sql:"expiresat"`
	Type      VerificationDataType `json:"type" sql:"type"`
}
