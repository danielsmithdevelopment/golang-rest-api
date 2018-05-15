package main

import (
	"fmt"
	"log"
	"net/http"

	"./models"
	uuid "github.com/satori/go.uuid"
)

var dbUsers = map[string]models.AppUser{}
var dbSessions = map[string]string{}

func getCookie(w http.ResponseWriter, req *http.Request) *http.Cookie {
	cookie, err := req.Cookie("session")
	if err != nil {
		cookie = setCookie(w, req)
	}
	// http.SetCookie(w, cookie)
	return cookie
}

func setCookie(w http.ResponseWriter, req *http.Request) *http.Cookie {

	sessionID, err := uuid.NewV4()
	if err != nil {
		log.Println("Logged error:", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
	cookie := &http.Cookie{
		Name:   "session",
		Value:  sessionID.String(),
		MaxAge: 0,
	}
	http.SetCookie(w, cookie)
	return cookie
}

func deleteCookie(w http.ResponseWriter, req *http.Request) {
	cookie := &http.Cookie{
		Name:   "session",
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(w, cookie)
}

func getUser(w http.ResponseWriter, req *http.Request) models.AppUser {
	cookie := getCookie(w, req)

	var u models.AppUser
	if un, ok := dbSessions[cookie.Value]; ok {
		u = dbUsers[un]
	}
	return u
}

func alreadyLoggedIn(w http.ResponseWriter, req *http.Request) bool {
	// fmt.Println("Path: ", ctx.Path())
	showSessions()
	cookie := getCookie(w, req)
	fmt.Println(cookie)
	if cookie == nil {
		return false
	}

	username, _ := dbSessions[cookie.Value]
	fmt.Println(username)
	_, ok := dbUsers[username]
	return ok
}

func showSessions() {
	fmt.Println("********")
	for k, v := range dbSessions {
		fmt.Println(k, v)
	}
	fmt.Println("")
}
