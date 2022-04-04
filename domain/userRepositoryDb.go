package domain

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jitin07/qastackauth/errs"
	"github.com/jitin07/qastackauth/logger"
	"github.com/jmoiron/sqlx"
)

type UserRepositoryDb struct {
	client *sqlx.DB
}

func (d UserRepositoryDb) GetUserByEmail(ctx context.Context, email string) (*Users, error) {
	logger.Debug("querying for user with email" + email)
	query := "select * from users where email = $1"
	var user Users
	if err := d.client.GetContext(ctx, &user, query, email); err != nil {
		return nil, err
	}
	return &user, nil
}

func (d UserRepositoryDb) GetUserByID(ctx context.Context, userID string) (*Users, error) {
	logger.Debug("querying for user with id" + userID)
	query := "select * from users where id = $1"
	var user Users
	if err := d.client.GetContext(ctx, &user, query, userID); err != nil {
		return nil, err
	}
	return &user, nil
}

// UpdatePassword updates the user password
func (repo UserRepositoryDb) UpdatePassword(ctx context.Context, email string, password string, tokenHash string) error {

	query := "update users set password = $1, tokenhash = $2 where email = $3"
	_, err := repo.client.ExecContext(ctx, query, password, tokenHash, email)
	return err
}

func (d UserRepositoryDb) GetAuthorisedRoutes(role_name string, email string) (*RolePermission, *errs.AppError) {
	var rolePermission RolePermission
	sqlVerify := "select routes from public.role_permission rp where role_id in (select id from public.roles where role_name=$1) and user_id in (select user_id from public.users where email=$2)"
	err := d.client.Get(&rolePermission, sqlVerify, role_name, email)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errs.NewAuthenticationError("invalid credentials")
		} else {
			logger.Error("Error while verifying login request from database: " + err.Error())
			return nil, errs.NewUnexpectedError("Unexpected database error")
		}
	}
	return &rolePermission, nil
}
func (d UserRepositoryDb) FindBy(username, password string) (*Login, *errs.AppError) {
	var login Login
	sqlVerify := "SELECT username ,role,isverified,email FROM users   WHERE email = $1 and password = $2"
	err := d.client.Get(&login, sqlVerify, username, password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errs.NewAuthenticationError("invalid credentials")
		} else {
			logger.Error("Error while verifying login request from database: " + err.Error())
			return nil, errs.NewUnexpectedError("Unexpected database error")
		}
	}
	return &login, nil
}

func (d UserRepositoryDb) RefreshTokenExists(refreshToken string) *errs.AppError {
	sqlSelect := "select refresh_token from refresh_token_store where refresh_token = $1"
	var token string
	err := d.client.Get(&token, sqlSelect, refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return errs.NewAuthenticationError("refresh token not registered in the store")
		} else {
			logger.Error("Unexpected database error: " + err.Error())
			return errs.NewUnexpectedError("unexpected database error")
		}
	}
	return nil
}

func (d UserRepositoryDb) GetAllUser() ([]Users, *errs.AppError) {
	var err error
	users := make([]Users, 0)
	//var users []Users

	findAllSql := "select users_id, username, password,email, role,project_id from users"
	err = d.client.Select(&users, findAllSql)

	if err != nil {
		fmt.Println("Error while querying customers table " + err.Error())
		return nil, errs.NewUnexpectedError("Unexpected database error")
	}

	return users, nil
}

func (d UserRepositoryDb) GetUserByUsername(username string) (*Users, *errs.AppError) {
	var users Users

	usernameSql := "select users_id, username, role from users where username = $1 "
	err := d.client.Get(&users, usernameSql, username)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errs.NewNotFoundError("User not found")
		} else {
			logger.Error("Error while scanning user " + err.Error())
			return nil, errs.NewUnexpectedError("Unexpected database error")
		}
	}
	return &users, nil
}

func (d UserRepositoryDb) AddUser(u Users) (*Users, *errs.AppError) {

	sqlInsert := "INSERT INTO users (username, password, email, role,created_at, updated_at,tokenhash) values ($1, $2,$3,$4,$5,$6,$7) RETURNING users_id"
	var userid int
	err := d.client.QueryRow(sqlInsert, u.Username, u.Password, u.Email, u.Role, u.CreatedAt, u.UpdatedAt, u.TokenHash).Scan(&userid)

	if err != nil {
		logger.Error("Error while creating new account: " + err.Error())
		return nil, errs.NewUnexpectedError("Unexpected error from database")
	}

	u.User_Id = userid
	return &u, nil

}

func (d UserRepositoryDb) GenerateAndSaveRefreshTokenToStore(authToken AuthToken) (string, *errs.AppError) {
	// generate the refresh token
	var appErr *errs.AppError
	var refreshToken string
	if refreshToken, appErr = authToken.newRefreshToken(); appErr != nil {
		return "", appErr
	}

	// store it in the store
	sqlInsert := "insert into refresh_token_store (refresh_token) values ($1)"
	_, err := d.client.Exec(sqlInsert, refreshToken)
	if err != nil {
		logger.Error("unexpected database error: " + err.Error())
		return "", errs.NewUnexpectedError("unexpected database error")
	}
	return refreshToken, nil
}

// StoreMailVerificationData adds a mail verification data to db
func (repo UserRepositoryDb) StoreVerificationData(ctx context.Context, verificationData *VerificationData) *errs.AppError {

	query := "insert into verifications(email, code, expiresat, type) values($1, $2, $3, $4)"
	_, err := repo.client.ExecContext(ctx, query, verificationData.Email, verificationData.Code, verificationData.ExpiresAt, verificationData.Type)
	if err != nil {
		logger.Error("Error while creating new verifications: " + err.Error())
		return errs.NewUnexpectedError("Unexpected error from database: verifications")
	}

	return nil

}

// UpdateUserVerificationStatus updates user verification status to true
func (repo UserRepositoryDb) UpdateUserVerificationStatus(ctx context.Context, email string, status bool) error {

	query := "update users set isverified = $1 where email = $2"
	if _, err := repo.client.ExecContext(ctx, query, status, email); err != nil {
		return err
	}
	return nil
}

// DeleteMailVerificationData deletes a used verification data
func (repo UserRepositoryDb) DeleteVerificationData(ctx context.Context, email string, verificationDataType VerificationDataType) error {

	query := "delete from verifications where email = $1 and type = $2"
	_, err := repo.client.ExecContext(ctx, query, email, verificationDataType)
	return err
}

func (repo UserRepositoryDb) GetVerificationData(ctx context.Context, email string, verificationDataType *VerificationDataType) (*VerificationData, error) {
	query := "select * from verifications where email = $1 and type = $2"

	var verificationData VerificationData
	if err := repo.client.GetContext(ctx, &verificationData, query, email, verificationDataType); err != nil {
		return nil, err
	}
	return &verificationData, nil
}

func (repo UserRepositoryDb) GetVerificationDataPasswordReset(ctx context.Context, email string, codeType int) (*VerificationData, error) {
	query := "select * from verifications where email = $1 and type = $2"

	var verificationData VerificationData
	if err := repo.client.GetContext(ctx, &verificationData, query, email, codeType); err != nil {
		return nil, err
	}
	return &verificationData, nil
}

func (repo UserRepositoryDb) GetVerificationDataUserInvite(ctx context.Context, email string) (*VerificationData, error) {
	query := "select * from users where email = $1"

	var verificationData VerificationData
	if err := repo.client.GetContext(ctx, &verificationData, query, email); err != nil {
		return nil, err
	}
	return &verificationData, nil
}
func NewUserRepositoryDb(dbClient *sqlx.DB) UserRepositoryDb {
	return UserRepositoryDb{dbClient}
}
