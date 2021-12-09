package app

import (
	"encoding/json"
	"fmt"
	"github.com/jitin07/qastackauth/domain"
	"github.com/jitin07/qastackauth/logger"
	"github.com/jitin07/qastackauth/service"
	"github.com/jmoiron/sqlx"
	"github.com/rs/cors"
	"os"
	"time"

	//"log"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"net/http"
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

	//sanityCheck()

	router := mux.NewRouter()
	dbClient := getDbClient()

	router.Use()
	userRepositoryDb := domain.NewUserRepositoryDb(dbClient)
	//wiring
	u := UserHandlers{service.NewUserService(userRepositoryDb,domain.GetRolePermissions())}

	// define routes

	router.HandleFunc("/api/auth/health", func (w http.ResponseWriter,r *http.Request) {
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


	router.HandleFunc("/auth/verify", u.Verify).Methods(http.MethodGet)
	//router.
	//	HandleFunc("/customers/{customer_id:[0-9]+}", ch.getCustomer).
	//	Methods(http.MethodGet).
	//	Name("GetCustomer")
	//router.
	//	HandleFunc("/customers/{customer_id:[0-9]+}/account", ah.NewAccount).
	//	Methods(http.MethodPost).
	//	Name("NewAccount")
	//router.
	//	HandleFunc("/customers/{customer_id:[0-9]+}/account/{account_id:[0-9]+}", ah.MakeTransaction).
	//	Methods(http.MethodPost).
	//	Name("NewTransaction")
	//
	//am := AuthMiddleware{domain.NewAuthRepository()}
	//router.Use(am.authorizationHandler())
	//// starting server
	//address := os.Getenv("SERVER_ADDRESS")
	//port := os.Getenv("SERVER_PORT")

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"http://localhost:3000"},
		AllowedHeaders: []string{ "Content-Type", "Authorization","Referer"},
		AllowCredentials: true,
		AllowedMethods: []string{"GET","PUT","DELETE","POST"},
	})

	handler := c.Handler(router)


	//logger.Info(fmt.Sprintf("Starting server on %s:%s ...", address, port))
	if err := http.ListenAndServe(":8090", handler); err != nil {
		fmt.Println("Failed to set up server")

	}

}


