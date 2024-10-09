package main

import (
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var secretKey, _ = rsa.GenerateKey(rand.Reader, 2048)

const dblog = "host=localhost port=5432 user=postgres password=123 dbname=medods sslmode=disable"

func main() {
	http.HandleFunc("/gettokens", Tokens)
	http.HandleFunc("/refreshtokens", RefreshTokens)
	http.HandleFunc("/getrefreshtoken", GetRefreshToken)
	http.ListenAndServe("localhost:8080", nil)
}

func Tokens(w http.ResponseWriter, r *http.Request) {
	guid := r.URL.Query().Get("guid")
	ip := r.RemoteAddr
	accessToken, refreshToken := CreateTokens(guid, ip)
	fmt.Fprintln(w, "Access token: "+accessToken)
	fmt.Fprintln(w, "Refresh token: "+refreshToken)
	UpdateUserRefreshToken(guid, refreshToken)
}

// сверяет совпадение ip внутри payload access токена и ip api запроса, отправляет сообщение в случае несовпадения
// возвращает новые access и refresh токены и обновляет refresh токен в БД
func RefreshTokens(w http.ResponseWriter, r *http.Request) {
	accessTokenString := r.URL.Query().Get("accesstoken")
	claims := jwt.MapClaims{}
	accessToken, _ := jwt.ParseWithClaims(accessTokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	fmt.Println(accessToken)
	guid := strings.Split(claims["sub"].(string), "/")[0]
	tokenip := strings.Split(claims["sub"].(string), "/")[1]
	senderip := r.RemoteAddr
	if tokenip != senderip {
		fmt.Fprintln(w, "Смена ip!")
	}
	newAccessToken, refreshToken := CreateTokens(guid, senderip)
	fmt.Fprintln(w, "Access token: "+newAccessToken)
	fmt.Fprintln(w, "Refresh token: "+refreshToken)
	UpdateUserRefreshToken(guid, refreshToken)
}

// возвращает refresh token, привязанный к guid пользователя на данный момент(нужно для проверки, что refresh токен вообще меняется)
func GetRefreshToken(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("postgres", dblog)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	guid := r.URL.Query().Get("guid")
	refreshToken := ""
	err = db.QueryRow(fmt.Sprintf("select refreshtoken from users where guid='%v'", guid)).Scan(&refreshToken)
	if err != nil {
		panic(err)
	}
	fmt.Fprint(w, refreshToken)
}

// Создаёт access токен с guid и ip в payload, а также бессрочный refresh токен
func CreateTokens(guid, ip string) (string, string) {
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 5)),
		Subject:   guid + "/" + ip,
	}).SignedString(secretKey)
	if err != nil {
		panic(err)
	}
	refreshToken := uuid.NewString()
	refreshToken = base64.StdEncoding.EncodeToString([]byte(refreshToken))
	return accessToken, refreshToken
}

// Создаёт/обновляет refresh токен, закреплённый в БД за пользователем с данным guid
func UpdateUserRefreshToken(guid, token string) {
	db, err := sql.Open("postgres", dblog)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	_, err = db.Exec(fmt.Sprintf("update users set refreshtoken='%v' where guid='%v'", refreshTokenHash, guid))
	if err != nil {
		panic(err)
	}
}
