package main

import (
	"net/http"
)

type apiConfig struct {
	fsVisits int
}

func main() {
	mux := http.NewServeMux()
	cfg := apiConfig{
		fsVisits: 0,
	}

	mux.Handle("/app/*", cfg.middlewareVisitsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	chirpyServer := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	mux.HandleFunc("GET /api/healthz", readinessHandler)

	mux.HandleFunc("GET /admin/metrics", cfg.metricsHandlerFunc)

	mux.HandleFunc("/api/reset", cfg.resetHandler)

	mux.HandleFunc("POST /api/validate_chirp", validationHandler)

	chirpyServer.ListenAndServe()
}
