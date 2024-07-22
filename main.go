package main

import (
	"net/http"
)

func main() {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(".")))
	chirpyServer := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	chirpyServer.ListenAndServe()
}
