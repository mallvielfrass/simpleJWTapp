package main

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/mallvielfrass/wst"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// Migrate the schema
	db.AutoMigrate(&User{})
	app := App{db}
	r := chi.NewRouter()
	//r.Use(wst.MiddlewareAllowCORS)
	r.Use(wst.MiddlewareURL)
	r.HandleFunc("/signup", app.signUp)
	r.HandleFunc("/signin", Signin)
	r.With(MiddlewareJWT).Route("/auth", func(r chi.Router) {
		r.HandleFunc("/welcome", Welcome)
	})

	r.HandleFunc("/refresh", Refresh)

	// r.With(wst.MiddlewareJSON).Route("/api", func(r chi.Router) {
	// 	//only not auth methods
	// 	r.With().Route("/nauth", func(r chi.Router) {
	// 		//r.HandleFunc("/register", register)
	// 		//	r.HandleFunc("/login", login)
	// 	})
	// 	//only auth methods
	// 	r.With().Route("/auth", func(r chi.Router) {
	// 		//r.HandleFunc("/profile", profile)
	// 	})
	// })
	wst.FileServer(r, "static")
	http.ListenAndServe(":3333", r)
}
