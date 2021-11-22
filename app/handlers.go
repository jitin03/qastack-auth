package app

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jitin07/qastackauth/dto"
	"github.com/jitin07/qastackauth/logger"
	"github.com/jitin07/qastackauth/service"
)

type UserHandlers struct {
	service service.UserService
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
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Set("Access-Control-Allow-Methods",  "GET,POST, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Authorization")
	var request dto.UsersRegisterRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		writeResponse(w, http.StatusBadRequest, err.Error())
	} else {

		userId, appError := u.service.AddUser(request)
		if appError != nil {
			writeResponse(w, appError.Code, appError.AsMessage())
		} else {
			writeResponse(w, http.StatusCreated, userId)
		}
	}
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

func (h *UserHandlers) Verify(w http.ResponseWriter, r *http.Request) {
	urlParams := make(map[string]string)

	// converting from Query to map type
	for k := range r.URL.Query() {
		urlParams[k] = r.URL.Query().Get(k)
	}

	if urlParams["token"] != "" {
		appErr := h.service.Verify(urlParams)
		if appErr != nil {
			writeResponse(w, appErr.Code, notAuthorizedResponse(appErr.Message))
		} else {
			writeResponse(w, http.StatusOK, authorizedResponse())
		}
	} else {
		writeResponse(w, http.StatusForbidden, notAuthorizedResponse("missing token"))
	}

}
