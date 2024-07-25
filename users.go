package main

import (
	"encoding/json"
	"github.com/srijan-raghavula/chirpy/internal/database"
	"golang.org/x/crypto/bcrypt"
	"net/http"
)

type userLogin struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	ExpiresInSec int    `json:"expires_in_seconds"`
}

const cost int = bcrypt.DefaultCost

func (usrCfg *userConfig) createUser(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	creds := userLogin{}
	err := decoder.Decode(&creds)
	if err != nil {
		respondWithError(w, err.Error())
		return
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(creds.Password), cost)
	if err != nil {
		respondWithError(w, err.Error())
		return
	}
	err = dbPath.AddUser(usrCfg.newUser(creds.Email, passwordHash))
	if err != nil {
		respondWithError(w, err.Error())
		return
	}

	user, err := dbPath.GetUser(usrCfg.id)
	if err != nil {
		respondWithError(w, err.Error())
		return
	}
	writeData, err := json.Marshal(user)
	w.WriteHeader(201)
	w.Write(writeData)
}

func (usrCfg *userConfig) newUser(email string, password []byte) (database.User, database.UserPassword) {
	user := database.User{
		Id:    usrCfg.getNewId(),
		Email: email,
	}
	passwordStruct := database.UserPassword{
		Id:       user.Id,
		Password: password,
	}
	return user, passwordStruct
}

func (usrCfg *userConfig) login(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	creds := userLogin{}
	err := decoder.Decode(&creds)
	if err != nil {
		respondWithError(w, err.Error())
		return
	}

	user, loginSuccess, err := dbPath.AuthUser(creds.Email, []byte(creds.Password))
	if err != nil {
		respondWithError(w, err.Error())
		return
	}

	writeData, err := json.Marshal(user)
	if err != nil {
		respondWithError(w, "error writing data")
		return
	}

	if !loginSuccess {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(writeData)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(writeData)
}
