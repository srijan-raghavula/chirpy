package main

import (
	"fmt"
	"net/http"
)

func (cfg *apiConfig) middlewareVisitsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fsVisits++
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) getVisitCount() int {
	return cfg.fsVisits
}

func (cfg *apiConfig) metricsHandlerFunc(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`
<html>

<body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
</body>

</html>
	`, cfg.fsVisits)))
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
}
