package dto

type PasswordResetReq struct {
	Password   string `json: "password"`
	Code       string `json: "code"`
	PasswordRe string `json:"password_re"`
}
