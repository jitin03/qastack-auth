package dto

type LoginRequest struct {
	Emailaddress string `json:"emailaddress"`
	Password     string `json:"password"`
}
