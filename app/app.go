package app

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jitin07/qastackauth/domain"
	"github.com/jitin07/qastackauth/service"
	"github.com/jmoiron/sqlx"
	//"log"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"net/http"
	//"os"
)

func getDbClient() *sqlx.DB {
	client, err := sqlx.ConnectContext(context.Background(), "postgres", "host=localhost port=5432 user=postgres dbname=postgres sslmode=disable password=postgres")
	if err != nil {
		panic(err)
	}
	return client
}

func Start() {

	//sanityCheck()

	router := mux.NewRouter()
	dbClient := getDbClient()


	userRepositoryDb := domain.NewUserRepositoryDb(dbClient)
	//wiring
	u := UserHandlers{service.NewUserService(userRepositoryDb,domain.GetRolePermissions())}

	//customerRepositoryDb := domain.NewCustomerRepositoryDb(dbClient)
	//accountRepositoryDb := domain.NewAccountRepositoryDb(dbClient)
	//ch := CustomerHandlers{service.NewCustomerService(customerRepositoryDb)}
	//ah := AccountHandler{service.NewAccountService(accountRepositoryDb)}

	// define routes

	router.HandleFunc("/api/health", func (w http.ResponseWriter,r *http.Request) {
		json.NewEncoder(w).Encode("Running...")
	})
	router.
		HandleFunc("/api/users", u.GetAllUsers).
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
	//logger.Info(fmt.Sprintf("Starting server on %s:%s ...", address, port))
	if err := http.ListenAndServe(":8090", router); err != nil {
		fmt.Println("Failed to set up server")

	}

}


