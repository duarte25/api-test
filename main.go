package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"github.com/duarte25/rest-api/auth"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// "Account type" (Conta)
type Account struct {
	Cpf    string `json:"cpf" db:"cpf"`
	Secret string `json:"secret" db:"secret"`
}

/*func CommonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, Access-Control-Request-Headers, Access-Control-Request-Method, Connection, Host, Origin, User-Agent, Referer, Cache-Control, X-header")
		next.ServeHTTP(w, r)
	})
}*/

func CreateUser(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./date.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	creds := &Account{}
	err = json.NewDecoder(r.Body).Decode(creds)
	if err != nil {
		// If there is something wrong with the request body, return a 400 status
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Secret), 8)

	_, err = db.Exec("insert into date values ($1, $2)", creds.Cpf, string(hashedPassword))
	if err != nil {
		// If there is any issue with inserting into the database, return a 500 error
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

}

func Login(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./date.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	creds := &Account{}
	err = json.NewDecoder(r.Body).Decode(creds)
	if err != nil {
		// If there is something wrong with the request body, return a 400 status
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	result, err := db.Query("SELECT secret FROM date WHERE cpf", creds.Cpf)
	if err != nil {
		panic(err.Error())
	}
	defer result.Close()

	var post Account
	for result.Next() {
		err := result.Scan(&post.Secret)
		if err != nil {
			panic(err.Error())
		}
	}
	// Compare the stored hashed password, with the hashed version of the password that was received
	err = bcrypt.CompareHashAndPassword([]byte(post.Secret), []byte(creds.Secret))
	if err != nil {
		return
	}

	json.NewEncoder(w).Encode(err)

}

func GetAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	db, err := sql.Open("sqlite3", "./date.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var posts []Account
	result, err := db.Query("SELECT cpf, secret from date")
	if err != nil {
		panic(err.Error())
	}
	defer result.Close()
	for result.Next() {
		var post Account
		err := result.Scan(&post.Cpf, &post.Secret)
		if err != nil {
			panic(err.Error())
		}
		posts = append(posts, post)

	}
	json.NewEncoder(w).Encode(posts)

}

func main() {
	db, err := sql.Open("sqlite3", "./date.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	r := mux.NewRouter().StrictSlash(true)
	//r.Use(CommonMiddleware)

	r.HandleFunc("/register", CreateUser).Methods("POST")
	r.HandleFunc("/login", Login).Methods("POST")
	r.HandleFunc("/user2", GetAccount).Methods("GET")
	log.Fatal(http.ListenAndServe(":8080", r))

	s := r.PathPrefix("/auth").Subrouter()
	s.Use(auth.Middleware)
	s.HandleFunc("/user", GetAccount).Methods("GET")

}
