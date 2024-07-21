package main

import (
	"net/http"
)

func main() {
	serveMux := http.NewServeMux()

	chirpyServer := http.Server{
		Handler: serveMux,
	}
	chirpyServer.ListenAndServe()
}
