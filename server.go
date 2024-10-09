package main

import (
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var secret_key, _ = rsa.GenerateKey(rand.Reader, 2048)

const dblog = "host=localhost port=5432 user=postgres password=123 dbname=medods sslmode=disable"

func main() {
	http.HandleFunc("/gettokens", Tokens)
	http.HandleFunc("/refreshtokens", RefreshTokens)
	http.ListenAndServe("localhost:8080", nil)
}

func Tokens(w http.ResponseWriter, r *http.Request) {
	guid := r.URL.Query().Get("guid")
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 5)),
		Subject:   guid + "/" + r.RemoteAddr,
	}).SignedString(secret_key)
	if err != nil {
		panic(err)
	}
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		Subject:   guid + "/" + r.RemoteAddr,
	}).SignedString(secret_key)
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(w, "Access token: "+accessToken)
	fmt.Fprintln(w, "Refresh token: "+refreshToken)
	UpdateUserRefreshToken(guid, refreshToken)
}

func RefreshTokens(w http.ResponseWriter, r *http.Request) {

}

func UpdateUserRefreshToken(guid, token string) {
	db, err := sql.Open("postgres", dblog)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(token), 10)
	if err != nil {
		panic(err)
	}
	_, err = db.Exec("update users set refreshToken=%v where guid=%v", refreshTokenHash, guid)
	if err != nil {
		panic(err)
	}
}
