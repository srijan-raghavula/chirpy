package main

import (
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/srijan-raghavula/chirpy/internal/database"
	"net/http"
	"strconv"
	"strings"
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

func (apiCfg *apiConfig) validateAndPOSTHandler(w http.ResponseWriter, r *http.Request) {

	decoder := json.NewDecoder(r.Body)
	rBody := reqBody{}
	err := decoder.Decode(&rBody)
	if err != nil {
		respondWithError(w, swwErrMsg)
		return
	}

	tokenStr := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	loggedIn, userId, err := dbPath.ValidateToken(tokenStr, apiCfg.jwtSecret)
	if err != nil {
		respondWithError(w, err.Error())
		return
	}

	if !loggedIn {
		w.WriteHeader(http.StatusUnauthorized)
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

	newId := apiCfg.getNewId()
	chirp := database.Chirp{
		Id:       newId,
		AuthorId: userId,
		Message:  rBody.Message,
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

func (apiCfg *apiConfig) removeChirp(w http.ResponseWriter, r *http.Request) {
	tokenStr := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	token, err := jwt.ParseWithClaims(tokenStr, &myClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(apiCfg.jwtSecret), nil
	})
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	chirpIdStr := r.PathValue("chirpID")
	chirpId, err := strconv.Atoi(chirpIdStr)
	if err != nil {
		respondWithError(w, err.Error())
	}

	authorIdStr, err := token.Claims.GetSubject()
	if err != nil {
		respondWithError(w, err.Error())
	}
	authorId, err := strconv.Atoi(authorIdStr)
	if err != nil {
		respondWithError(w, err.Error())
	}
	if chirpId != authorId {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	err = dbPath.RemoveChirp(chirpId)
	if err != nil {
		respondWithError(w, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func respondWithError(w http.ResponseWriter, msg string) {
	writeData, _ := json.Marshal(errBody{
		Message: msg,
	})
	w.WriteHeader(500)
	w.Write(writeData)
}
