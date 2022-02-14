package app

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jitin07/qastackauth/domain"
	"github.com/jitin07/qastackauth/logger"
	"github.com/jitin07/qastackauth/service"
	"github.com/jitin07/qastackauth/utils"
	"github.com/jmoiron/sqlx"
	"github.com/rs/cors"

	//"log"
	"net/http"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	//"os"
)

func getDbClient() *sqlx.DB {

	dbUser := os.Getenv("DB_USER")
	dbPasswd := os.Getenv("DB_PASSWD")
	dbAddr := os.Getenv("DB_ADDR")
	//dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		dbAddr, 5432, dbUser, dbPasswd, dbName)
	logger.Info(psqlInfo)
	client, err := sqlx.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}
	// See "Important settings" section.
	client.SetConnMaxLifetime(time.Minute * 3)
	client.SetMaxOpenConns(10)
	client.SetMaxIdleConns(10)

	//client, err := sqlx.ConnectContext(context.Background(), "postgres",os.Getenv("DATABASE_URL") )
	//if err != nil {
	//	panic(err)
	//}
	return client
}

func Start() {

	logger := utils.NewLogger()

	configs := utils.NewConfigurations(logger)

	// validator contains all the methods that are need to validate the user json in request
	validator := domain.NewValidation()

	// mailService contains the utility methods to send an email
	mailService := service.NewSGMailService(logger, configs)

	router := mux.NewRouter()
	dbClient := getDbClient()

	router.Use()
	userRepositoryDb := domain.NewUserRepositoryDb(dbClient)
	defer dbClient.Close()
	//wiring
	u := UserHandlers{service.NewUserService(userRepositoryDb, domain.GetRolePermissions()), mailService, logger, configs, validator}

	// define routes

	router.HandleFunc("/api/auth/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode("Running...")
	})
	router.
		HandleFunc("/api/auth/users", u.GetAllUsers).
		Methods(http.MethodGet)

	router.
		HandleFunc("/api/users/{username}", u.GetUser).
		Methods(http.MethodGet)

	router.
		HandleFunc("/api/users/register", u.RegisterUser).
		Methods(http.MethodPost)

	router.HandleFunc("/auth/login", u.Login).Methods(http.MethodPost)

	router.HandleFunc("/auth/refresh", u.Refresh).Methods(http.MethodPost)

	router.HandleFunc("/auth/verify", u.Verify).Methods(http.MethodGet)

	mailR := router.PathPrefix("/verify").Methods(http.MethodGet).Subrouter()
	mailR.HandleFunc("/email", u.VerifyMail)
	mailR.HandleFunc("/password-reset", u.VerifyPasswordReset)
	// mailR.Use(u.MiddlewareValidateVerificationData)

	getR := router.Methods(http.MethodGet).Subrouter()

	getR.HandleFunc("/get-password-reset-code", u.GeneratePassResetCode)
	// getR.Use(u.MiddlewareValidateAccessToken)

	putR := router.Methods(http.MethodPut).Subrouter()

	putR.HandleFunc("/reset-password", u.ResetPassword)

	// putR.Use(u.MiddlewareValidateAccessToken)

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedHeaders:   []string{"Content-Type", "Authorization", "Referer"},
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "PUT", "DELETE", "POST"},
	})

	handler := c.Handler(router)

	//logger.Info(fmt.Sprintf("Starting server on %s:%s ...", address, port))
	if err := http.ListenAndServe(":8090", handler); err != nil {
		fmt.Println("Failed to set up server")

	}

}
