package main

import (
	"flag"
	"github.com/srijan-raghavula/chirpy/internal/database"
	"net/http"
	"os"
	"sync"
)

type apiConfig struct {
	fsVisits int
	id       int
}

type userConfig struct {
	id int
}

var dbPath = database.DBPath{
	Path: "database.json",
	Mu:   &sync.RWMutex{},
}

func main() {
	dbg := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()
	if *dbg {
		os.Remove("database.json")
	}

	mux := http.NewServeMux()
	apiCfg := apiConfig{
		fsVisits: 0,
		id:       0,
	}
	usrCfg := userConfig{
		id: 0,
	}

	mux.Handle("/app/*", apiCfg.middlewareVisitsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	chirpyServer := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	mux.HandleFunc("GET /api/healthz", readinessHandler)

	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandlerFunc)

	mux.HandleFunc("/api/reset", apiCfg.resetHandler)

	mux.HandleFunc("POST /api/chirps", apiCfg.validateAndPOSTHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.getAllChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirp)

	mux.HandleFunc("POST /api/users", usrCfg.createUser)
	mux.HandleFunc("POST /api/login", usrCfg.login)

	chirpyServer.ListenAndServe()
}
