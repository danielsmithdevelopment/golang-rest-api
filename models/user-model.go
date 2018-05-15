package models

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"../config"
	"github.com/gorilla/mux"
)

type App struct {
	Router      *mux.Router
	apiRouter   *mux.Router
	adminRouter *mux.Router
	DB          *sql.DB
}

type AppUser struct {
	ID        int    `json:"id,omitempty"`
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
	Email     string `json:"email,omitempty"`
	Password  []byte `json:"password,omitempty"`
}

// ----------------------- Helper methods below ----------------------
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

func main() {}

// ----------------------- Helper methods above ----------------------

// -------------------------- User CRUD Below ------------------------
func (u *AppUser) GetUser(db *sql.DB) error {
	statement := fmt.Sprintf("SELECT firstName, lastName, email, password FROM users WHERE id=%d", u.ID)
	return db.QueryRow(statement).Scan(
		&u.FirstName,
		&u.LastName,
		&u.Email,
		&u.Password)
}
func (u *AppUser) UpdateUser(db *sql.DB) error {
	statement := fmt.Sprintf("UPDATE users SET firstName='%s', lastName='%s', email='%s', password='%s' WHERE id=%d", u.FirstName, u.LastName, u.Email, u.Password, u.ID)
	_, err := db.Exec(statement)
	return err
}
func (u *AppUser) DeleteUser(db *sql.DB) error {
	statement := fmt.Sprintf("DELETE FROM users WHERE id=%d", u.ID)
	_, err := db.Exec(statement)
	return err
}
func (u *AppUser) CreateUser(db *sql.DB) error {
	statement := fmt.Sprintf("INSERT INTO users(firstName, lastName, email, password) VALUES('%s', '%s', '%s', '%s')", u.FirstName, u.LastName, u.Email, u.Password)
	_, err := db.Exec(statement)
	if err != nil {
		return err
	}
	err = db.QueryRow("SELECT LAST_INSERT_ID()").Scan(&u.ID)
	if err != nil {
		return err
	}
	return nil
}
func GetUsers(db *sql.DB, start, count int) ([]AppUser, error) {
	statement := fmt.Sprintf("SELECT id, firstName, lastName, email, password FROM users LIMIT %d OFFSET %d", count, start)
	rows, err := db.Query(statement)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := []AppUser{}
	for rows.Next() {
		var u AppUser
		if err := rows.Scan(&u.ID, &u.FirstName, &u.LastName, &u.Email, &u.Password); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

// -------------------------- User CRUD Above ------------------------

func GetUsersHandler(w http.ResponseWriter, req *http.Request) {
	var users []AppUser
	users, err := GetUsers(config.DB, 0, 10)
	// fmt.Println(users, err)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
	}
	respondWithJSON(w, http.StatusOK, users)
}
func CreateUserHandler(w http.ResponseWriter, req *http.Request) {
	var user = AppUser{2, "text", "was", "here", []byte("password")}
	err := user.CreateUser(config.DB)
	// fmt.Println(users, err)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
	}
	respondWithJSON(w, http.StatusOK, user)
}

// updateUserHandler updates user data whose id matches request param with new JSON data
func UpdateUserHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}
	var u AppUser
	decoder := json.NewDecoder(req.Body)
	if err := decoder.Decode(&u); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid resquest payload")
		return
	}
	defer req.Body.Close()
	u.ID = id
	if err := u.UpdateUser(config.DB); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, u)
}

// deleteUserHandler takes user ID and deletes matching user with ID
func DeleteUserHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid User ID")
		return
	}
	u := AppUser{ID: id}
	if err := u.DeleteUser(config.DB); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, map[string]string{"result": "success"})
}

// getUserHandler returns user with matching id
func GetUserHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}
	u := AppUser{ID: id}
	if err := u.GetUser(config.DB); err != nil {
		switch err {
		case sql.ErrNoRows:
			respondWithError(w, http.StatusNotFound, "User not found")
		default:
			respondWithError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	respondWithJSON(w, http.StatusOK, u)
}
