package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/mallvielfrass/fmc"
)

func (app App) MiddlewareJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// We can obtain the session token from the requests cookies, which come with every request
		c, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				// If the cookie is not set, return an unauthorized status
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// For any other type of error, return a bad request status
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Get the JWT string from the cookie
		tknStr := c.Value

		// Initialize a new instance of `Claims`
		claims := &ClaimsToken{}

		// Parse the JWT string and store the result in `claims`.
		// Note that we are passing the key in this method as well. This method will return an error
		// if the token is invalid (if it has expired according to the expiry time we set on sign in),
		// or if the signature does not match
		tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !tkn.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmc.PrintStruct(claims)
		userRefHash := claims.RefreshHash
		var tokBase TokenBase
		if err := app.DB.Where("user_id = ? and uuid = ?", claims.Username, claims.RefreshUUID).First(&tokBase).Error; err != nil {
			fmt.Printf("%s not exist\n", claims.Username)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// hashPass, err := HashPassword(tokBase.TokenRefresh)
		// if err != nil {
		// 	// If the cookie is not set, return an unauthorized status
		// 	fmt.Printf("D1 %s\n", err.Error())
		// 	w.WriteHeader(http.StatusUnauthorized)
		// 	return
		// }
		fmt.Printf("userRefHash: [%s] | hashPass: %s\n", userRefHash, tokBase.TokenRefresh)
		b := CheckPasswordHash(tokBase.TokenRefresh, userRefHash)
		if !b {
			fmt.Printf("D2\n")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if claims.ExpiresAt < time.Now().Unix() {
			fmt.Printf("D3\n")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		r.AddCookie(&http.Cookie{Name: "name", Value: claims.Username, Expires: time.Now().Add(5 * 60 * time.Second)})
		next.ServeHTTP(w, r)
	})
}
