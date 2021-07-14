package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/mallvielfrass/fmc"
)

var jwtKey = []byte("my_secret_key")
var jwtKeyRefresh = []byte("my_secret_key2")
var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

// Create a struct that models the structure of a user, both in the request body, and in the DB
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

//
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}
type ClaimsToken struct {
	Username    string `json:"username"`
	RefreshUUID string
	RefreshHash string
	jwt.StandardClaims
}

func (app App) signUp(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	b, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(b, &creds)
	if err != nil {
		fmt.Println(err)
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if creds.Username == "" || creds.Password == "" {
		fmt.Println(err)
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var user User
	if err := app.DB.Where("name = ?", creds.Username).First(&user).Error; err == nil {
		fmt.Printf("%s exist\n", creds.Username)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	hashPass, err := HashPassword(creds.Password)
	fmc.ErrorHandle(err, "Hashing password")
	data := time.Now() //.Format("2006.01.02 15:04:05")
	u := User{
		Name:         creds.Username,
		Data:         data,
		PasswordHash: hashPass,
	}
	result := app.DB.Create(&u)
	fmt.Println(result)
	//Refresh___________________________________
	tokenRefresh, expirationTimeRefresh, err := CreateRefreshToken(creds)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	RefreshUUID := generageRandomString(16)
	RefreshHash, err := HashPassword(tokenRefresh)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	token, tokenExp, err := CreateToken(creds, RefreshHash, RefreshUUID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   token,
		Expires: tokenExp,
	})

	http.SetCookie(w, &http.Cookie{
		Name:    "refresh",
		Value:   tokenRefresh,
		Expires: expirationTimeRefresh,
	})

	http.RedirectHandler("/welcome", http.StatusMovedPermanently)
}
func Signin(w http.ResponseWriter, r *http.Request) {

	var creds Credentials
	b, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(b, &creds)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Get the expected password from our in memory map
	expectedPassword, ok := users[creds.Username]
	fmt.Printf("log: %s ; pass: %s\n", creds.Username, creds.Password)

	if !ok || expectedPassword != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Declare the expiration time of the token
	// here, we have kept it as 5 minutes
	expirationTime := time.Now().Add(5 * time.Minute)
	// Create the JWT claims, which includes the username and expiry time
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		// If there is an error in creating the JWT return an internal server error
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Finally, we set the client cookie for "token" as the JWT we just generated
	// we also set an expiry time which is the same as the token itself
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}

func Welcome(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("name")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	tknStr := c.Value

	w.Write([]byte(fmt.Sprintf("Welcome %s!", tknStr)))
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	// (BEGIN) The code uptil this point is the same as the first part of the `Welcome` route
	c, err := r.Cookie("token")
	fmt.Printf("cookie_: %s\n", c.Value)
	if err != nil {
		fmt.Println(err)
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tknStr := c.Value
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if !tkn.Valid {
		fmt.Println("unvalid")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			fmt.Println("unvalid2")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// (END) The code uptil this point is the same as the first part of the `Welcome` route

	// We ensure that a new token is not issued until enough time has elapsed
	// In this case, a new token will only be issued if the old token is within
	// 30 seconds of expiry. Otherwise, return a bad request status
	//if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 10*time.Second {
	//	fmt.Println("unvalid3")
	//	w.WriteHeader(http.StatusBadRequest)
	//	return
	//}

	// Now, create a new token for the current use, with a renewed expiration time
	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		fmt.Println("unvalid4s")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Set the new token as the users `session_token` cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}
