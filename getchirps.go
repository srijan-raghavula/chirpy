package main

import (
	"encoding/json"
	"github.com/srijan-raghavula/chirpy/internal/database"
	"net/http"
	"sort"
	"strconv"
)

func (cfg *apiConfig) getAllChirps(w http.ResponseWriter, r *http.Request) {

	data, err := dbPath.GetChirps("database.json")
	if err != nil {
		respondWithError(w, err.Error())
		return
	}

	var dataJSON database.DBStructure
	err = json.Unmarshal(data, &dataJSON)
	if err != nil {
		respondWithError(w, "Error unmarshaling database")
		return
	}

	var chirpSlice []database.Chirp
	for _, v := range dataJSON.Chirps {
		chirpSlice = append(chirpSlice, v)
	}

	sort.Slice(chirpSlice, func(i, j int) bool { return chirpSlice[i].Id < chirpSlice[j].Id })
	writeData, err := json.Marshal(chirpSlice)
	if err != nil {
		respondWithError(w, "Error writing response")
		return
	}

	w.Write(writeData)
	w.WriteHeader(http.StatusOK)
}

func (cfg *apiConfig) getChirp(w http.ResponseWriter, r *http.Request) {

	data, err := dbPath.GetChirps("database.json")
	if err != nil {
		respondWithError(w, err.Error())
		return
	}

	var dataJSON database.DBStructure
	err = json.Unmarshal(data, &dataJSON)
	if err != nil {
		respondWithError(w, "Error unmarshaling database")
		return
	}

	strid := r.PathValue("chirpID")
	id, err := strconv.Atoi(strid)
	if err != nil {
		respondWithError(w, "String conversion error")
		return
	}

	val, ok := dataJSON.Chirps[id]
	if !ok {
		w.WriteHeader(404)
		return
	}

	writeData, err := json.Marshal(val)
	w.Write(writeData)
	w.WriteHeader(http.StatusFound)
}
