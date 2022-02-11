package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/hashicorp/go-hclog"
	"github.com/jitin07/qastackauth/domain"
	"github.com/jitin07/qastackauth/dto"
	"github.com/jitin07/qastackauth/logger"
	"github.com/jitin07/qastackauth/service"
	"github.com/jitin07/qastackauth/utils"
	"github.com/labstack/gommon/log"
)

// VerificationDataKey is used as the key for storing the VerificationData in context at middleware
type VerificationDataKey struct{}

// UserKey is used as a key for storing the User object in context at middleware
type UserKey struct{}

// UserIDKey is used as a key for storing the UserID in context at middleware
type UserIDKey struct{}
type UserHandlers struct {
	service     service.UserService
	mailService service.MailService
	logger      hclog.Logger
	configs     *utils.Configurations
	validator   *domain.Validation
}

func (u *UserHandlers) GetAllUsers(w http.ResponseWriter, r *http.Request) {

	users, err := u.service.GetAllUser()

	if err != nil {
		fmt.Println("Inside error" + err.Message)

		writeResponse(w, err.Code, err.AsMessage())
	} else {
		fmt.Println("Inside error")
		writeResponse(w, http.StatusOK, users)
	}

}

func (u UserHandlers) GetUser(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	username := params["username"]

	user, err := u.service.GetUserByUsername(username)

	if err != nil {

		writeResponse(w, err.Code, err.AsMessage())
	} else {

		writeResponse(w, http.StatusOK, user)
	}

}

func (u UserHandlers) RegisterUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Authorization")
	w.Header().Set("Content-Type", "application/json")
	var request dto.UsersRegisterRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		writeResponse(w, http.StatusBadRequest, err.Error())
	} else {

		_, appError := u.service.AddUser(request)
		if appError != nil {

			u.logger.Error("unable to insert user to database", "error", err)
			ToJSON(&dto.GenericResponse{Status: false, Message: dto.UserCreationFailed}, w)
			return

		}

		// Send verification mail
		from := "jitin.doriya@gmail.com"
		to := []string{request.Email}
		subject := "Email Verification for QAStack"
		mailType := service.MailConfirmation
		mailData := &service.MailData{
			Email: request.Email,
			Code:  utils.GenerateUUID(),
		}

		mailReq := u.mailService.NewMail(from, to, subject, mailType, mailData)
		err = u.mailService.SendMail(mailReq)
		if err != nil {
			u.logger.Error("unable to send mail", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			ToJSON(&dto.GenericResponse{Status: false, Message: dto.UserCreationFailed}, w)

			return
		}

		verificationData := &domain.VerificationData{
			Email:     request.Email,
			Code:      mailData.Code,
			Type:      domain.MailConfirmation,
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(u.configs.MailVerifCodeExpiration)),
		}

		appErr := u.service.StoreVerificationData(context.Background(), verificationData)
		if appErr != nil {
			u.logger.Error("unable to store mail verification data", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			ToJSON(&dto.GenericResponse{Status: false, Message: dto.UserCreationFailed}, w)
			return
		}

		u.logger.Debug("User created successfully")
		w.WriteHeader(http.StatusCreated)
		// ToJSON(&GenericMessage{Message: "user created successfully"}, w)

		ToJSON(&dto.GenericResponse{Status: true, Message: "Please verify your email account using the confirmation code send to your mail"}, w)
	}
}

// VerifyMail verifies the provided confirmation code and set the User state to verified
func (ah *UserHandlers) VerifyMail(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	ah.logger.Debug("verifying the confimation code")
	verificationData := domain.VerificationData{}
	verificationData.Type = domain.MailConfirmation
	verificationData.Email = r.URL.Query().Get("email")
	verificationData.Code = r.URL.Query().Get("code")

	actualVerificationData, err := ah.service.GetVerificationData(context.Background(), verificationData.Email, &verificationData.Type)
	if err != nil {
		ah.logger.Error("unable to fetch verification data", "error", err)

		if strings.Contains(err.Error(), dto.PgNoRowsMsg) {
			w.WriteHeader(http.StatusNotAcceptable)
			ToJSON(&dto.GenericResponse{Status: false, Message: dto.ErrUserNotFound}, w)
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		ToJSON(&dto.GenericResponse{Status: false, Message: "Unable to verify mail. Please try again later"}, w)
		return
	}

	valid, err := ah.verify(actualVerificationData, &verificationData)
	if !valid {
		w.WriteHeader(http.StatusNotAcceptable)
		ToJSON(&dto.GenericResponse{Status: false, Message: err.Error()}, w)
		return
	}

	// correct code, update user status to verified.
	err = ah.service.UpdateUserVerificationStatus(context.Background(), verificationData.Email, true)
	if err != nil {
		ah.logger.Error("unable to set user verification status to true")
		w.WriteHeader(http.StatusInternalServerError)
		ToJSON(&dto.GenericResponse{Status: false, Message: "Unable to verify mail. Please try again later"}, w)
		return
	}

	// delete the VerificationData from db
	err = ah.service.DeleteVerificationData(context.Background(), verificationData.Email, verificationData.Type)
	if err != nil {
		ah.logger.Error("unable to delete the verification data", "error", err)
	}

	ah.logger.Debug("user mail verification succeeded")

	w.WriteHeader(http.StatusAccepted)
	ToJSON(&dto.GenericResponse{Status: true, Message: "Mail Verification succeeded"}, w)
}

// GeneratePassResetCode generate a new secret code to reset password.
func (ah *UserHandlers) GeneratePassResetCode(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	// userID := r.Context().Value(UserIDKey{}).(string)
	userID := r.URL.Query().Get("email")

	user, err := ah.service.GetUserByEmail(context.Background(), userID)
	if err != nil {
		ah.logger.Error("unable to get user to generate secret code for password reset", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		ToJSON(&dto.GenericResponse{Status: false, Message: "Unable to send password reset code. Please try again later"}, w)
		return
	}

	// Send verification mail
	from := "jitin.doriya@gmail.com"
	to := []string{user.Email}
	subject := "Password Reset for QAStack"
	mailType := service.PassReset
	mailData := &service.MailData{
		Email: user.Email,
		Code:  utils.GenerateUUID(),
	}

	mailReq := ah.mailService.NewMail(from, to, subject, mailType, mailData)
	err = ah.mailService.SendMail(mailReq)
	if err != nil {
		ah.logger.Error("unable to send mail", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		ToJSON(&dto.GenericResponse{Status: false, Message: "Unable to send password reset code. Please try again later"}, w)
		return
	}

	// store the password reset code to db
	verificationData := &domain.VerificationData{
		Email:     user.Email,
		Code:      mailData.Code,
		Type:      domain.PassReset,
		ExpiresAt: time.Now().Add(time.Minute * time.Duration(ah.configs.PassResetCodeExpiration)),
	}

	appErr := ah.service.StoreVerificationData(context.Background(), verificationData)
	if appErr != nil {
		ah.logger.Error("unable to store password reset verification data", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		ToJSON(&dto.GenericResponse{Status: false, Message: "Unable to send password reset code. Please try again later"}, w)
		return
	}

	ah.logger.Debug("successfully mailed password reset code")
	w.WriteHeader(http.StatusOK)
	ToJSON(&dto.GenericResponse{Status: true, Message: "Please check your mail for password reset code"}, w)
}

// VerifyPasswordReset verifies the code provided for password reset
func (ah *UserHandlers) VerifyPasswordReset(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	ah.logger.Debug("verifing password reset code")
	verificationData := r.Context().Value(VerificationDataKey{}).(domain.VerificationData)
	verificationData.Type = domain.PassReset

	actualVerificationData, err := ah.service.GetVerificationData(context.Background(), verificationData.Email, &verificationData.Type)
	if err != nil {
		ah.logger.Error("unable to fetch verification data", "error", err)
		if strings.Contains(err.Error(), dto.PgNoRowsMsg) {
			w.WriteHeader(http.StatusNotAcceptable)
			ToJSON(&dto.GenericResponse{Status: false, Message: dto.ErrUserNotFound}, w)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		ToJSON(&dto.GenericResponse{Status: false, Message: "Unable to reset password. Please try again later"}, w)
		return
	}

	valid, err := ah.verify(actualVerificationData, &verificationData)
	if !valid {
		w.WriteHeader(http.StatusNotAcceptable)
		ToJSON(&dto.GenericResponse{Status: false, Message: err.Error()}, w)
		return
	}

	respData := struct {
		Code string
	}{
		Code: verificationData.Code,
	}

	ah.logger.Debug("password reset code verification succeeded")
	w.WriteHeader(http.StatusAccepted)
	ToJSON(&dto.GenericResponse{Status: true, Message: "Password Reset code verification succeeded", Data: respData}, w)
}

func (ah *UserHandlers) verify(actualVerificationData *domain.VerificationData, verificationData *domain.VerificationData) (bool, error) {

	// check for expiration
	if actualVerificationData.ExpiresAt.Before(time.Now()) {
		ah.logger.Error("verification data provided is expired")
		err := ah.service.DeleteVerificationData(context.Background(), actualVerificationData.Email, actualVerificationData.Type)
		ah.logger.Error("unable to delete verification data from db", "error", err)
		return false, errors.New("Confirmation code has expired. Please try generating a new code")
	}

	ah.logger.Debug(actualVerificationData.Code)
	ah.logger.Debug(verificationData.Code)
	if actualVerificationData.Code != verificationData.Code {
		ah.logger.Error("verification of mail failed. Invalid verification code provided")
		return false, errors.New("Verification code provided is Invalid. Please look in your mail for the code")
	}

	return true, nil
}
func (h UserHandlers) Login(w http.ResponseWriter, r *http.Request) {
	var loginRequest dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		logger.Error("Error while decoding login request: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		token, appError := h.service.Login(loginRequest)
		if appError != nil {
			writeResponse(w, appError.Code, appError.AsMessage())
		} else {
			writeResponse(w, http.StatusOK, *token)
		}
	}
}

func (h *UserHandlers) Refresh(w http.ResponseWriter, r *http.Request) {

	var refreshRequest dto.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&refreshRequest); err != nil {
		logger.Error("Error while decoding refresh token request: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		token, appErr := h.service.Refresh(refreshRequest)
		if appErr != nil {
			writeResponse(w, appErr.Code, appErr.AsMessage())
		} else {
			writeResponse(w, http.StatusOK, *token)
		}
	}
}
func (h *UserHandlers) Verify(w http.ResponseWriter, r *http.Request) {
	urlParams := make(map[string]string)

	// converting from Query to map type
	for k := range r.URL.Query() {
		urlParams[k] = r.URL.Query().Get(k)
	}

	if urlParams["token"] != "" {
		appErr := h.service.Verify(urlParams)
		if appErr != nil {
			writeResponse(w, appErr.Code, NotAuthorizedResponse(appErr.Message))
		} else {
			writeResponse(w, http.StatusOK, authorizedResponse())
		}
	} else {
		writeResponse(w, http.StatusForbidden, NotAuthorizedResponse("missing token"))
	}

}

// PasswordReset handles the password reset request
func (ah *UserHandlers) ResetPassword(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	email := r.URL.Query().Get("email")
	code := r.URL.Query().Get("code")

	var passResetReq dto.PasswordResetReq
	passResetReq.Code = code
	if err := json.NewDecoder(r.Body).Decode(&passResetReq); err != nil {

		ah.logger.Error("unable to decode password reset request json", "error", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		ToJSON(&dto.GenericResponse{Status: false, Message: err.Error()}, w)
		return
	}

	log.Info(email)
	user, err := ah.service.GetUserByEmail(context.Background(), email)
	if err != nil {
		ah.logger.Error("unable to retrieve the user from db", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		ToJSON(&dto.GenericResponse{Status: false, Message: "Unable to reset password. Please try again later"}, w)
		return
	}

	actualVerificationData, err := ah.service.GetVerificationDataPasswordReset(context.Background(), user.Email, 2)

	if err != nil {
		ah.logger.Error("unable to fetch verification data", "error", err)

		if strings.Contains(err.Error(), dto.PgNoRowsMsg) {
			w.WriteHeader(http.StatusNotAcceptable)
			ToJSON(&dto.GenericResponse{Status: false, Message: dto.ErrUserNotFound}, w)
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		ToJSON(&dto.GenericResponse{Status: false, Message: "Unable to verify mail. Please try again later"}, w)
		return
	}

	if actualVerificationData.Code != passResetReq.Code {
		// we should never be here.
		ah.logger.Error("verification code did not match even after verifying PassReset")
		w.WriteHeader(http.StatusInternalServerError)
		ToJSON(&dto.GenericResponse{Status: false, Message: "Unable to reset password. Please try again later"}, w)
		return
	}

	if passResetReq.Password != passResetReq.PasswordRe {
		ah.logger.Error("password and password re-enter did not match")
		w.WriteHeader(http.StatusNotAcceptable)
		ToJSON(&dto.GenericResponse{Status: false, Message: "Password and re-entered Password are not same"}, w)
		return
	}

	// hashedPass, err := ah.hashPassword(passResetReq.Password)
	// if err != nil {
	// 	w.WriteHeader(http.StatusInternalServerError)
	// 	data.ToJSON(&GenericResponse{Status: false, Message: UserCreationFailed}, w)
	// 	return
	// }

	tokenHash := utils.GenerateRandomString(15)
	err = ah.service.UpdatePassword(context.Background(), email, passResetReq.Password, tokenHash)
	if err != nil {
		ah.logger.Error("unable to update user password in db", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		ToJSON(&dto.GenericResponse{Status: false, Message: "Password and re-entered Password are not same"}, w)
		return
	}

	// delete the VerificationData from db
	err = ah.service.DeleteVerificationData(context.Background(), actualVerificationData.Email, actualVerificationData.Type)
	if err != nil {
		ah.logger.Error("unable to delete the verification data", "error", err)
	}

	w.WriteHeader(http.StatusOK)
	ToJSON(&dto.GenericResponse{Status: false, Message: "Password Reset Successfully"}, w)
}
