package main

import (
	"flag"
	"github.com/joho/godotenv"
	"github.com/srijan-raghavula/chirpy/internal/database"
	"log"
	"net/http"
	"os"
	"sync"
)

type apiConfig struct {
	fsVisits    int
	id          int
	jwtSecret   string
	polkaAPIKey string
}

type userConfig struct {
	id int
}

var dbPath = database.DBPath{
	Path: "database.json",
	Mu:   &sync.RWMutex{},
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalln("Error loading file:", err)
	}

	dbg := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()
	if *dbg {
		os.Remove("database.json")
	}

	mux := http.NewServeMux()
	secret := os.Getenv("JWT_SECRET")
	apiKey := os.Getenv("POLKA_KEY")
	apiCfg := apiConfig{
		fsVisits:    0,
		id:          0,
		jwtSecret:   secret,
		polkaAPIKey: apiKey,
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
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.removeChirp)

	mux.HandleFunc("POST /api/users", usrCfg.createUser)
	mux.HandleFunc("PUT /api/users", apiCfg.updateUserCreds)

	mux.HandleFunc("POST /api/login", apiCfg.login)
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshToken)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeToken)

	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.upgradeUser)

	log.Println("Server running")
	chirpyServer.ListenAndServe()
}
