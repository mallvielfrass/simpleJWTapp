package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/mallvielfrass/fmc"
	"github.com/mallvielfrass/wst"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

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
	//___________________________________
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
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "refresh",
		Value:   tokenStringRefresh,
		Expires: expirationTimeRefresh,
	})

	http.RedirectHandler("/welcome", http.StatusMovedPermanently)
}
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
