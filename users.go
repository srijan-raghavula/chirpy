package main

import (
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/srijan-raghavula/chirpy/internal/database"
	"github.com/srijan-raghavula/chirpy/internal/secret"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strings"
	"time"
)

type userLogin struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	ExpiresInSec int    `json:"expires_in_seconds"`
}

type myClaims struct {
	jwt.RegisteredClaims
}

const cost int = bcrypt.DefaultCost

func (usrCfg *userConfig) createUser(w http.ResponseWriter, r *http.Request) {
	log.Println("creting user")
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
	log.Println("user added")
	if err != nil {
		respondWithError(w, err.Error())
		return
	}

	user, err := dbPath.GetUser(usrCfg.id)
	log.Println("got user")
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
	log.Println("logging in")
	decoder := json.NewDecoder(r.Body)
	creds := userLogin{}
	err := decoder.Decode(&creds)
	if err != nil {
		respondWithError(w, err.Error())
		return
	}

	user, loginSuccess, err := dbPath.AuthUser(creds.Email, []byte(creds.Password), cfg.jwtSecret, creds.ExpiresInSec)
	log.Println("user authed")
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
	log.Println("updating user")
	decoder := json.NewDecoder(r.Body)
	newCreds := database.Creds{}

	tokenStr := func() string {
		header := r.Header.Get("Authorization")
		if separated := strings.Split(header, " "); separated[0] == "Bearer" {
			return separated[1]
		}
		return ""
	}()
	token, err := jwt.ParseWithClaims(tokenStr, &myClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(apiCfg.jwtSecret), nil
	})
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	err = decoder.Decode(&newCreds)
	if err != nil {
		respondWithError(w, err.Error())
		return
	}

	updatedUser, err := dbPath.UpdateUser(token, newCreds)
	log.Println("user updated")
	if err != nil {
		respondWithError(w, err.Error())
		return
	}
	writeData, err := json.Marshal(updatedUser)
	if err != nil {
		respondWithError(w, err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(writeData)
}

func (apiCfg *apiConfig) refreshToken(w http.ResponseWriter, r *http.Request) {
	log.Println("refreshing token")
	tokenStr := func() string {
		header := r.Header.Get("Authorization")
		if separated := strings.Split(header, " "); separated[0] == "Bearer" {
			return separated[1]
		}
		return ""
	}()

	valid, userId, err := dbPath.ValidateToken(tokenStr)
	log.Println("token validated")
	if err != nil {
		respondWithError(w, err.Error())
	}
	if !valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	tokenStr, err = secret.GetToken(userId, time.Duration(3600*time.Second), apiCfg.jwtSecret)
	log.Println("got refresh token")
	if err != nil {
		respondWithError(w, err.Error())
	}

	body := struct {
		Token string `json:"token"`
	}{
		Token: tokenStr,
	}
	writeData, err := json.Marshal(body)
	w.WriteHeader(http.StatusOK)
	w.Write(writeData)
}

func (apiCfg *apiConfig) revokeToken(w http.ResponseWriter, r *http.Request) {
	log.Println("revoking token")
	tokenStr := func() string {
		header := r.Header.Get("Authorization")
		if separated := strings.Split(header, " "); separated[0] == "Bearer" {
			return separated[1]
		}
		return ""
	}()

	err := dbPath.RemoveToken(tokenStr)
	log.Println("token removed")
	if err != nil {
		respondWithError(w, err.Error())
	}
	w.WriteHeader(http.StatusNoContent)
}
