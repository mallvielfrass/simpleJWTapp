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
