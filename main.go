// Copyright 2018 Daniel Smith. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Golang REST Server with Swagger
//
// This documentation describes example APIs found under https://github.com/danielsmithdevelopment/golang-rest-api
//
//     Schemes: https
//     BasePath: /v1
//     Version: 1.0.0
//     License: MIT http://opensource.org/licenses/MIT
//     Contact: Daniel Smith <danielsmithdevelopment@gmail.com> https://danielsmithdevelopment.com
//     Host: https://github.com/danielsmithdevelopment/golang-rest-api
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Security:
//     - bearer
//
//     SecurityDefinitions:
//     bearer:
//          type: apiKey
//          name: Authorization
//          in: header
//
// swagger:meta
package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"./config"
	"./models"
	"github.com/gorilla/mux"
	"github.com/jtblin/go-ldap-client"
	"golang.org/x/crypto/bcrypt"
)

type tomlConfig struct {
	Default      string                 `toml:"default"` // Determines which environment to use
	Environments map[string]environment `toml:"env"`
}

type environment struct {
	ApiUrl string `toml:"ApiUrl"`
	Port   string `toml:"Port"`
}

// auth holds all values used for authentication in this applicaton
type auth struct {
	Username string
	Password string
}

// Nav holds values used in the generation of the navigation bar.
type nav struct {
	Username       string
	LoginFullName  string
	LoginWholeName string
	LoggedUserID   int
}

// TemplateVars holds all variables to render a template.
type templateVars struct {
	Title        string
	Nav          nav
	LoginError   bool
	ErrorMessage string
	UserList     []models.AppUser
	CurrentUser  models.AppUser
	PageName     string
	ReturnURL    string
	AdminUser    bool
}

var (
	router            *mux.Router
	dbSessionsCleaned time.Time
)

var tpl *template.Template
var siteTitle = "REST Server"

// ------------------------- Helper Methods Below ---------------------------
// RespondWithError is called on an error to return info regarding error
func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"error": message})
}

// Called for responses to encode and send json data
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	// encode payload to json
	response, _ := json.Marshal(payload)

	// set headers and write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

func todayDate() string {
	today := time.Now().Format("Jan 02 2006")
	return today
}

func todayLogFilename() string {
	filename := todayDate() + ".txt"
	return filename
}

func newLogFile() *os.File {
	file := todayLogFilename()

	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}

	return f
}

// ------------------------- Helper Methods Above ---------------------------
func init() {
	bs, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	dbUsers["danieljsmith93@gmail.com"] = models.AppUser{ID: 1, FirstName: "Daniel", LastName: "Smith", Email: "danieljsmith93@gmail.com", Password: bs}
	dbSessionsCleaned = time.Now()
	showSessions()
	router = mux.NewRouter()
	tpl = template.Must(template.ParseGlob("./static/templates/*"))
}

func main() {
	f := newLogFile()
	defer f.Close()
	fmt.Println("Connection to database successful")
	showSessions()

	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	router.HandleFunc("/", index).Methods("GET")
	router.HandleFunc("/index", index).Methods("GET")
	router.HandleFunc("/home", index).Methods("GET")
	router.HandleFunc("/login", login).Methods("GET")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/logout", logout).Methods("GET")
	router.HandleFunc("/signup", signup).Methods("GET")
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/manage-data/users", manageDataUsers).Methods("GET")
	router.HandleFunc("/manage-profile", manageProfile).Methods("GET")

	// // register api routes
	router.HandleFunc("/api/users", models.GetUsersHandler).Methods("GET")
	router.HandleFunc("/api/user/{id:[0-9]+}", models.GetUserHandler).Methods("GET")

	// // register admin api routes
	router.HandleFunc("/api/admin/user", models.CreateUserHandler).Methods("POST")
	router.HandleFunc("/api/admin/user/{id:[0-9]+}", models.UpdateUserHandler).Methods("PUT")
	router.HandleFunc("/api/admin/user/{id:[0-9]+}", models.DeleteUserHandler).Methods("DELETE")

	fmt.Println("Server started on http://localhost:8080")
	fmt.Println("Press CTRL + C to shutdown server")

	log.Fatal(http.ListenAndServe(":8080", router))
}

func index(w http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(w, req) {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}
	var tv templateVars
	tplErr := tpl.ExecuteTemplate(w, "index.html", tv)
	if tplErr != nil {
		log.Println("Logged error:", tplErr)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

// ===================================================
func (a *auth) ldapBind() (bool, error) {
	fullLDAPName := a.Username + "@domain.extension"
	client := &ldap.LDAPClient{
		Base:         "dc=domain,dc=extension",
		Host:         "xx.x.x.xx",
		Port:         000,
		UseSSL:       false,
		BindDN:       fullLDAPName,
		BindPassword: a.Password,
		UserFilter:   "(uid=%s)",
		GroupFilter:  "(memberUid=%s)",
		Attributes:   []string{"givenName", "sn", "mail", "uid"},
	}

	// It is the responsibility of the caller to close the connection
	defer client.Close()

	err := client.Connect()
	if err != nil {
		log.Printf("%v", err.Error())
		log.Printf("%v", fmt.Sprintf("USER:%s failed to CONNECT with the LDAP server.", fullLDAPName))
		return false, err
	}

	_, _, err = client.Authenticate(fullLDAPName, a.Password)

	if err != nil {
		// TODO: Find out if this is because our users can't search, on the LDAP namespace
		if err.Error() != "User does not exist" {
			log.Printf("%v", err.Error())
			log.Printf("%v", fmt.Sprintf("USER:%s failed to AUTHENTICATE with the LDAP server.", fullLDAPName))
			return false, err
		}
	}

	return true, nil
} //end of LDAP building
// ===================================================

func login(w http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(w, req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	// loggedIn, err := a.ldapBind()
	var tv templateVars
	if req.Method == http.MethodPost {
		var loginAuth auth
		loginAuth = auth{Username: req.FormValue("email"), Password: req.FormValue("password")}
		fmt.Println("checking login: ", loginAuth.Username, loginAuth.Password)
		u, ok := dbUsers[loginAuth.Username]
		fmt.Println("checking user returned from memory: ", u, ok)
		if !ok {
			http.Error(w, "Username and/or password do not match", http.StatusForbidden)
			return
		}

		loginError := bcrypt.CompareHashAndPassword(u.Password, []byte(loginAuth.Password))
		if loginError != nil {
			fmt.Println(loginError)
			http.Error(w, "Username and/or password do not match", http.StatusForbidden)
			return
		}
		c := getCookie(w, req)
		fmt.Println(c)

		dbSessions[c.Value] = loginAuth.Username
		bs, _ := bcrypt.GenerateFromPassword([]byte(loginAuth.Password), bcrypt.MinCost)
		user := models.AppUser{1, "first", "last", loginAuth.Username, bs}
		dbUsers[loginAuth.Username] = user
		http.Redirect(w, req, "/index", http.StatusSeeOther)
	}

	tplErr := tpl.ExecuteTemplate(w, "login.html", tv)

	if tplErr != nil {
		log.Println("Logged error:", tplErr)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}
func logout(w http.ResponseWriter, req *http.Request) {
	cookie := getCookie(w, req)
	delete(dbSessions, cookie.Value)
	deleteCookie(w, req)
	http.Redirect(w, req, "/login", http.StatusSeeOther)
}
func signup(w http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(w, req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	var tv templateVars
	if req.Method == http.MethodPost {
		first := req.FormValue("firstName")
		last := req.FormValue("lastName")
		email := req.FormValue("email")
		pass, err := bcrypt.GenerateFromPassword([]byte(req.FormValue("password")), bcrypt.MinCost)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		fmt.Println(first, last, email, pass)

		if _, ok := dbUsers[email]; ok {
			http.Error(w, "Username already taken", http.StatusForbidden)
			return
		}

		c := getCookie(w, req)

		dbSessions[c.Value] = email

		u := models.AppUser{ID: 1, FirstName: first, LastName: last, Email: email, Password: pass}
		dbUsers[email] = u
		http.Redirect(w, req, "/login", http.StatusSeeOther)
	}
	tplErr := tpl.ExecuteTemplate(w, "signup.html", tv)

	if tplErr != nil {
		log.Println("Logged error:", tplErr)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}
func manageDataUsers(w http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(w, req) {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}
	var tv templateVars
	tv.UserList, _ = models.GetUsers(config.DB, 0, 10)
	fmt.Println("template vars: ", tv)
	tplErr := tpl.ExecuteTemplate(w, "manage-users.html", tv)

	if tplErr != nil {
		log.Println("Logged error:", tplErr)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}
func manageProfile(w http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(w, req) {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	var tv templateVars
	tplErr := tpl.ExecuteTemplate(w, "manage-profile.html", tv)

	if tplErr != nil {
		log.Println("Logged error:", tplErr)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}
