package main

import (
	"log"
	"net/http"

	"github.com/cemenson/basic-go-jwt-auth/controller"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/register",
		controller.RegisterHandler).
		Methods("POST")

	r.HandleFunc("/login",
		controller.LoginHandler).
		Methods("POST")

	r.HandleFunc("/logout",
		controller.TokenValidate(
			controller.LogoutHandler)).
		Methods("POST")

	r.HandleFunc("/token/refresh",
		controller.TokenValidate(
			controller.RefreshTokenHandler)).
		Methods("POST")

	r.HandleFunc("/account",
		controller.TokenValidate(
			controller.AccountHandler)).
		Methods("GET")

	log.Fatal(http.ListenAndServe(":8080", r))
}
