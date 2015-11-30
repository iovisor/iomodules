// vim: set ts=8:sts=8:sw=8:noet

package hive

import (
	"database/sql"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

var schema = `
CREATE TABLE person (
    first_name text,
    last_name text,
    email text
);

CREATE TABLE place (
    country text,
    city text NULL,
    telcode integer
)`

type person struct {
	FirstName string `db:"first_name"`
	LastName  string `db:"last_name"`
	Email     string
}

type place struct {
	Country string
	City    sql.NullString
	TelCode int
}

var db *sqlx.DB

func Connect() {
	db = sqlx.MustConnect("sqlite3", ":memory:")
	db.Exec(schema)
}
