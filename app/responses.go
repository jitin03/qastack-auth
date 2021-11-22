package app

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jitin07/qastackauth/errs"
)

func setupCorsResponse(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	(*w).Header().Set("Access-Control-Allow-Methods",  "GET,POST,OPTIONS,PUT,DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Authorization")
}

// JSON returns a well formated response with a status code
func JSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	setupCorsResponse(&w)
	w.WriteHeader(statusCode)

	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		fmt.Fprintf(w, "%s", err.Error())
	}
}

// ERROR returns a jsonified error response along with a status code.
func ERROR(w http.ResponseWriter, statusCode int, err *errs.AppError) {
	w.Header().Set("Content-Type", "application/json")
	setupCorsResponse(&w)

	JSON(w, http.StatusBadRequest, err)
}

func notAuthorizedResponse(msg string) map[string]interface{} {
	return map[string]interface{}{
		"isAuthorized": false,
		"message":      msg,
	}
}

func authorizedResponse() map[string]bool {
	return map[string]bool{"isAuthorized": true}
}

func writeResponse(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Add("Content-Type", "application/json")
	setupCorsResponse(&w)
	w.WriteHeader(code)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		panic(err)
	}
}
