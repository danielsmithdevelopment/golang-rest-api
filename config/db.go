package config

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

func init() {
	// connect to db
	// connectionString := fmt.Sprintf("%s:%s@/%s", username, password, dbname)
	connectionString := fmt.Sprintf("%s:%s@/%s", "mysql", "mysql", "site_db")
	var err error

	// connect to sql database using connection string
	DB, err = sql.Open("mysql", connectionString)
	if err != nil {
		log.Fatal(err)
	}

	if err = DB.Ping(); err != nil {
		log.Fatal(err)
	}
}
