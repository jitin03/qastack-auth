package app

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/jitin07/qastackauth/domain"
	"github.com/jitin07/qastackauth/dto"
)

// MiddlewareValidateUser validates the user in the request
func (ah *UserHandlers) MiddlewareValidateUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")

		ah.logger.Debug("user json", r.Body)
		user := &domain.Users{}

		err := FromJSON(user, r.Body)
		if err != nil {
			ah.logger.Error("deserialization of user json failed", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			// ToJSON(&GenericError{Error: err.Error()}, w)
			ToJSON(&dto.GenericResponse{Status: false, Message: err.Error()}, w)
			return
		}

		// validate the user
		errs := ah.validator.Validate(user)
		if len(errs) != 0 {
			ah.logger.Error("validation of user json failed", "error", errs)
			w.WriteHeader(http.StatusBadRequest)
			// ToJSON(&ValidationError{Errors: errs.Errors()}, w)
			ToJSON(&dto.GenericResponse{Status: false, Message: strings.Join(errs.Errors(), ",")}, w)
			return
		}

		// add the user to the context
		ctx := context.WithValue(r.Context(), UserKey{}, *user)
		r = r.WithContext(ctx)

		// call the next handler
		next.ServeHTTP(w, r)
	})
}

// MiddlewareValidateAccessToken validates whether the request contains a bearer token
// it also decodes and authenticates the given token
func (ah *UserHandlers) MiddlewareValidateAccessToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		urlParams := make(map[string]string)

		// converting from Query to map type
		for k := range r.URL.Query() {
			urlParams[k] = r.URL.Query().Get(k)
		}

		if urlParams["token"] != "" {
			appErr := ah.service.Verify(urlParams)
			if appErr != nil {
				writeResponse(w, appErr.Code, NotAuthorizedResponse(appErr.Message))
			} else {
				writeResponse(w, http.StatusOK, authorizedResponse())
			}
		} else {
			writeResponse(w, http.StatusForbidden, NotAuthorizedResponse("missing token"))
		}

		next.ServeHTTP(w, r)
	})
}

func (ah *UserHandlers) MiddlewareValidateVerificationData(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")
		ah.logger.Debug("validating verification data")

		verificationData := &domain.VerificationData{}

		err := FromJSON(verificationData, r.Body)
		if err != nil {
			ah.logger.Error("deserialization of verification data failed", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			ToJSON(&dto.GenericResponse{Status: false, Message: err.Error()}, w)
			return
		}

		errs := ah.validator.Validate(verificationData)
		if len(errs) != 0 {
			ah.logger.Error("validation of verification data json failed", "error", errs)
			w.WriteHeader(http.StatusBadRequest)
			ToJSON(&dto.GenericResponse{Status: false, Message: strings.Join(errs.Errors(), ",")}, w)
			return
		}

		// add the ValidationData to context
		ctx := context.WithValue(r.Context(), VerificationDataKey{}, *verificationData)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func extractToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	authHeaderContent := strings.Split(authHeader, " ")
	if len(authHeaderContent) != 2 {
		return "", errors.New("Token not provided or malformed")
	}
	return authHeaderContent[1], nil
}
