package main

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name         string
	Data         time.Time
	PasswordHash string
}
type App struct {
	DB *gorm.DB
}
type TokenBase struct {
	UserID       string
	TokenRefresh string
	UUID         string
	Data         time.Time
}
