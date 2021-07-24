package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type Account struct {
	Cpf    string `json:"cpf" db:"cpf"`
	Secret string `json:"secret" db:"secret"`
}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var header = r.Header.Get("x-access-token") //Grab the token from the header

		header = strings.TrimSpace(header)

		if header == "" {
			//Token is missing, returns with error code 403 Unauthorized
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode("Missing auth token")
			return
		}

		db, err := sql.Open("sqlite3", "./date.db")
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()

		creds := &Account{}
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

		err = bcrypt.CompareHashAndPassword([]byte(post.Secret), []byte(creds.Secret))
		if err != nil {
			return
		}

		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode("Missing auth Senha")
			return
		}

		ctx := context.WithValue(r.Context(), "main", post)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
