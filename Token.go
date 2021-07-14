package main

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

func CreateRefreshToken(creds Credentials) (string, int64, error) {
	expirationTimeRefresh := time.Now().Add(30 * 24 * time.Hour)
	claimsRefresh := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTimeRefresh.Unix(),
		},
	}
	// Declare the token with the algorithm used for signing, and the claims
	tokenRefresh := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsRefresh)
	// Create the JWT string
	tokenStringRefresh, err := tokenRefresh.SignedString(jwtKeyRefresh)
	if err != nil {
		return "", 0, err
	}
	return tokenStringRefresh, expirationTimeRefresh.Unix(), nil
}
func CreateToken(creds Credentials, RefreshHash string, RefreshUUID string) (string, int64, error) {
	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &ClaimsToken{
		Username:    creds.Username,
		RefreshUUID: RefreshUUID,
		RefreshHash: RefreshHash,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", expirationTime.Unix(), err
	}
	return tokenString, expirationTime.Unix(), nil
}
