package main

import (
	"net/http"
)

func readinessHandler(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(http.StatusText(http.StatusOK)))
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
}
