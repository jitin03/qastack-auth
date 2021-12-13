package domain

import (
	"database/sql"
	"fmt"

	"github.com/jitin07/qastackauth/errs"
	"github.com/jitin07/qastackauth/logger"
	"github.com/jmoiron/sqlx"
)

type UserRepositoryDb struct {
	client *sqlx.DB
}

func (d UserRepositoryDb) FindBy(username, password string) (*Login, *errs.AppError) {
	var login Login
	sqlVerify := "SELECT username ,role FROM users   WHERE username = $1 and password = $2"
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

func (d UserRepositoryDb) GetAllUser()([]Users,*errs.AppError){
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

func (d UserRepositoryDb) GetUserByUsername(username string)(*Users,*errs.AppError)  {
	var users Users
	logger.Info(username)
	usernameSql := "select users_id, username, role from users where username = $1 "
	err := d.client.Get(&users, usernameSql,username)


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

func (d UserRepositoryDb) AddUser(u Users) (*Users,*errs.AppError) {

	sqlInsert := "INSERT INTO users (username, password, email, role) values ($1, $2,$3,$4) RETURNING users_id"
	var userid int
	err := d.client.QueryRow(sqlInsert, u.Username, u.Password, u.Email, u.Role).Scan(&userid)


	if err != nil {
		logger.Error("Error while creating new account: " + err.Error())
		return nil, errs.NewUnexpectedError("Unexpected error from database")
	}

	u.User_Id = userid
	return &u, nil


}


func NewUserRepositoryDb(dbClient *sqlx.DB) UserRepositoryDb{
	return UserRepositoryDb{dbClient}
}