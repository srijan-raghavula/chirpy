package main

import (
	"encoding/json"
	"github.com/srijan-raghavula/chirpy/internal/database"
	"net/http"
)

type reqBody struct {
	Message string `json:"body"`
}
type validity struct {
	Message bool `json:"valid"`
}
type errBody struct {
	Message string `json:"error"`
}

var swwErrMsg string = "Something went wrong"

func (cfg *apiConfig) validateAndPOSTHandler(w http.ResponseWriter, r *http.Request) {

	decoder := json.NewDecoder(r.Body)
	rBody := reqBody{}
	err := decoder.Decode(&rBody)
	if err != nil {
		respondWithError(w, swwErrMsg)
		return
	}

	chirpLength := len(rBody.Message)
	if chirpLength > 140 {
		w.WriteHeader(400)
		writeData, err := json.Marshal(errBody{
			Message: "Chirp is too long",
		})
		if err != nil {
			respondWithError(w, swwErrMsg)
			return
		}
		w.Write(writeData)
		return
	}

	newId := cfg.getNewId()
	chirp := database.Chirp{
		Id:      newId,
		Message: rBody.Message,
	}

	err = dbPath.AddChirp(chirp)
	if err != nil {
		respondWithError(w, err.Error())
		return
	}

	writeData, err := json.Marshal(chirp)
	if err != nil {
		respondWithError(w, swwErrMsg)
		return
	}
	w.WriteHeader(201)
	w.Write(writeData)
}

func respondWithError(w http.ResponseWriter, msg string) {
	writeData, _ := json.Marshal(errBody{
		Message: msg,
	})
	w.WriteHeader(500)
	w.Write(writeData)
}
