package main

import (
	"encoding/json"
	"log"
	"net/http"
)

func validationHandler(w http.ResponseWriter, r *http.Request) {
	type body struct {
		Message string `json:"body"`
	}
	type validity struct {
		Message bool `json:"valid"`
	}
	type errBody struct {
		Message string `json:"error"`
	}

	decoder := json.NewDecoder(r.Body)
	reqBody := body{}
	err := decoder.Decode(&reqBody)
	if err != nil {
		log.Printf("decode error: %q", err)
		w.WriteHeader(500)
		return
	}

	chirpLength := len(reqBody.Message)
	if chirpLength > 140 {
		w.WriteHeader(400)
		writeData, err := json.Marshal(errBody{
			Message: "Chirp is too long",
		})
		if err != nil {
			log.Printf("marshaling error: %q", err)
			w.WriteHeader(500)
			return
		}
		w.Write(writeData)
		return
	}

	writeData, err := json.Marshal(validity{
		Message: true,
	})
	if err != nil {
		writeData, _ := json.Marshal(errBody{
			Message: "Something went wrong",
		})
		w.Write(writeData)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(writeData)
}
