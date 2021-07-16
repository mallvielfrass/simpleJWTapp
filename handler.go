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
	err = app.DB.Create(&u).Error
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Println(u)
	//Refresh___________________________________
	tokenRefresh, expirationTimeRefresh, err := CreateRefreshToken(creds.Username)
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

	token, tokenExp, err := CreateToken(creds.Username, RefreshHash, RefreshUUID)
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
	t := TokenBase{
		UserID:       creds.Username,
		TokenRefresh: tokenRefresh,
		UUID:         RefreshUUID,
		Data:         time.Now(),
	}
	err = app.DB.Create(&t).Error
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, "{'res':'ok'}")
	//	http.RedirectHandler("/welcome", http.StatusMovedPermanently)
}
func (app App) Signin(w http.ResponseWriter, r *http.Request) {
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
	if err := app.DB.Where("name = ?", creds.Username).First(&user).Error; err != nil {
		fmt.Printf("%s not exist\n", creds.Username)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	fmt.Println(user)
	tokenRefresh, expirationTimeRefresh, err := CreateRefreshToken(creds.Username)
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

	token, tokenExp, err := CreateToken(creds.Username, RefreshHash, RefreshUUID)
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
	t := TokenBase{
		UserID:       creds.Username,
		TokenRefresh: tokenRefresh,
		UUID:         RefreshUUID,
		Data:         time.Now(),
	}
	err = app.DB.Create(&t).Error
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, "{'res':'ok'}")
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

func (app App) Refresh(w http.ResponseWriter, r *http.Request) {
	// (BEGIN) The code uptil this point is the same as the first part of the `Welcome` route
	c, err := r.Cookie("refresh")
	fmt.Printf("cookie_refresh: %s\n", c.Value)
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
		return jwtKeyRefresh, nil
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
	if claims.ExpiresAt < time.Now().Unix() {
		fmt.Println("unvalid3")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var tokBase TokenBase
	if err := app.DB.Where("user_id = ? and token_refresh = ?", claims.Username, tknStr).First(&tokBase).Error; err != nil {
		fmt.Printf("%s not exist\n", claims.Username)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	app.DB.Where("user_id = ? and token_refresh = ?", claims.Username, tknStr).Delete(&tokBase)
	tokenRefresh, expirationTimeRefresh, err := CreateRefreshToken(claims.Username)
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

	token, tokenExp, err := CreateToken(claims.Username, RefreshHash, RefreshUUID)
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
	t := TokenBase{
		UserID:       claims.Username,
		TokenRefresh: tokenRefresh,
		UUID:         RefreshUUID,
		Data:         time.Now(),
	}
	err = app.DB.Create(&t).Error
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, "{'res':'ok'}")
}
