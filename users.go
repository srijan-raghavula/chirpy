package main

import (
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/srijan-raghavula/chirpy/internal/database"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strings"
	"time"
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

func (cfg *apiConfig) login(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	creds := userLogin{}
	err := decoder.Decode(&creds)
	if err != nil {
		respondWithError(w, err.Error())
		return
	}

	user, loginSuccess, err := dbPath.AuthUser(creds.Email, []byte(creds.Password), cfg.jwtSecret, creds.ExpiresInSec)
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

func (apiCfg *apiConfig) updateUserCreds(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	newCreds := database.Creds{}

	tokenStr := strings.TrimPrefix("Bearer ", r.Header.Get("token"))
	token, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{Issuer: "chirpy"}, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return []byte{}, errors.New("different signing method")
		}
		if issuer, _ := token.Claims.GetIssuer(); issuer != "chirpy" {
			return []byte{}, errors.New("invalid issuer")
		}

		expirationTime, _ := token.Claims.GetExpirationTime()
		if time.Now().After(expirationTime.Time) {
			return []byte{}, errors.New("token expired")
		}

		return apiCfg.jwtSecret, nil
	})

	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized access"))
	}

	err = decoder.Decode(&newCreds)
	if err != nil {
		respondWithError(w, err.Error())
	}

	updatedUser, err := dbPath.UpdateUser(token, newCreds)
	if err != nil {
		respondWithError(w, err.Error())
	}
	writeData, err := json.Marshal(updatedUser)
	if err != nil {
		respondWithError(w, err.Error())
	}
	w.WriteHeader(http.StatusOK)
	w.Write(writeData)
}
