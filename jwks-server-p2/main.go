package main

import (
	"log"
	"net/http"
)

/*
Entry point.
Opens (or creates) the SQLite key store and starts the server on port 8080.
The DB file name is required by the project spec: totally_not_my_privateKeys.db
*/
func main() {
	s, err := NewServer(DBFile)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("JWKS server listening on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", s.Routes()))
}
