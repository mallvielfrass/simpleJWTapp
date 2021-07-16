package main

import (
	"fmt"
	"testing"
)

func TestPasword(t *testing.T) {
	pass := "password"
	h1, err := HashPassword(pass)
	if err != nil {
		t.Errorf("Error: \n\thandle Err: %s\n", err)
	}
	h2, err := HashPassword(pass)
	if err != nil {
		t.Errorf("Error: \n\thandle Err: %s\n", err)
	}
	fmt.Printf("hash1: %s,T:%t|\nhash2: %s,T:%t|\n", h1, CheckPasswordHash(pass, h1), h2, CheckPasswordHash(pass, h2))

}
