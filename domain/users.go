package domain

import (
	"database/sql"
	"github.com/jitin07/qastackauth/dto"
	"github.com/jitin07/qastackauth/errs"
)

type Users struct {
	User_Id int		`db:"users_id"`
	Username string `db:"username"`
	Password string	`db:"password"`
	Email string 	`db:"email"`
	Role string		`db:"role"`
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



type UsersRepository interface {
	AddUser(user Users)(*Users, *errs.AppError)
	GetUserByUsername(string)(*Users,*errs.AppError)
	GetAllUser()([]Users,*errs.AppError)
	FindBy(username string, password string) (*Login, *errs.AppError)
}

