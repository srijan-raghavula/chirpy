package main

import (
	"net/http"
)

func (cfg *apiConfig) visitReset() bool {
	cfg.fsVisits = 0
	if cfg.fsVisits == 0 {
		return true
	}
	return false
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(200)
	isReset := cfg.visitReset()
	if isReset {
		w.Write([]byte("Hit count reset successfully"))
		w.Header().Add("Content-Type", "text/plain; charset=utf-8")
		return
	}
	w.Write([]byte("Failed to reset"))
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
}
