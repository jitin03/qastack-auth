package dto



type UsersRegisterRequest struct {
	User_Id int		`json:"users_id"`
	Username string `json:"username"`
	Password string	`json:"password"`
	Email string 	`json:"email"`
	Role string		`json:"role"`


}
