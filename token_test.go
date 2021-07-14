package main

import (
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func TestCreateRefreshToken(t *testing.T) {
	c := Credentials{
		Username: "userx",
	}
	str, _, err := CreateRefreshToken(c)
	if err != nil {
		t.Errorf("Error: \n\thandle Err: %s\n", err)
	}
	if len(strings.Split(str, ".")) != 3 {
		t.Errorf("Error isJWT(): %s\n", err)
	}
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(str, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKeyRefresh, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			t.Errorf("Error :ErrSignatureInvalid %s\n", str)
		}
	}
	if !tkn.Valid {
		t.Errorf("Error :TokenNotValid %s %v\n", str, claims)
	}
}
func TestCreateToken(t *testing.T) {
	c := Credentials{
		Username: "userx",
	}
	str, _, err := CreateRefreshToken(c)
	if err != nil {
		t.Errorf("Error: \n\thandle Err: %s\n", err)
	}
	RefreshHash, err := HashPassword(str)
	if err != nil {
		t.Errorf("Error: \n\thandle Err: %s\n", err)
	}
	RefreshUUID := generageRandomString(16)
	token, _, err := CreateToken(c, RefreshHash, RefreshUUID)
	if err != nil {
		t.Errorf("Error: \n\thandle Err: %s\n", err)
	}
	claims := &ClaimsToken{}

	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			t.Errorf("Error :ErrSignatureInvalid %s\n", str)
		}
	}
	if !tkn.Valid {
		t.Errorf("Error :TokenNotValid %s %v\n", str, claims)
	}
	if claims.ExpiresAt < time.Now().Add(4*time.Minute).Unix() {
		t.Errorf("Error :Token expired %d\n", claims.ExpiresAt)
	}
}
