package main

import (
	"encoding/json"
	"github.com/srijan-raghavula/chirpy/internal/database"
	"net/http"
	"sort"
	"strconv"
)

func (apiCfg *apiConfig) getAllChirps(w http.ResponseWriter, r *http.Request) {

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

	queryStr := r.URL.Query().Get("author_id")
	querySort := r.URL.Query().Get("sort")

	if queryStr != "" && querySort == "desc" {
		query, err := strconv.Atoi(queryStr)
		if err != nil {
			respondWithError(w, err.Error())
		}
		for _, v := range dataJSON.Chirps {
			if v.AuthorId == query {
				chirpSlice = append(chirpSlice, v)
			}
		}
		sort.Slice(chirpSlice, func(i, j int) bool { return chirpSlice[i].Id > chirpSlice[j].Id })
		writeData, err := json.Marshal(chirpSlice)
		if err != nil {
			respondWithError(w, "Error writing response")
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(writeData)
		return
	}

	if queryStr != "" {
		query, err := strconv.Atoi(queryStr)
		if err != nil {
			respondWithError(w, err.Error())
		}
		for _, v := range dataJSON.Chirps {
			if v.AuthorId == query {
				chirpSlice = append(chirpSlice, v)
			}
		}
		w.WriteHeader(http.StatusOK)
		writeData, err := json.Marshal(chirpSlice)
		if err != nil {
			respondWithError(w, err.Error())
		}
		w.Write(writeData)
		return
	}

	if querySort == "desc" {
		for _, v := range dataJSON.Chirps {
			chirpSlice = append(chirpSlice, v)
		}

		sort.Slice(chirpSlice, func(i, j int) bool { return chirpSlice[i].Id > chirpSlice[j].Id })
		writeData, err := json.Marshal(chirpSlice)
		if err != nil {
			respondWithError(w, "Error writing response")
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(writeData)
		return
	}

	for _, v := range dataJSON.Chirps {
		chirpSlice = append(chirpSlice, v)
	}

	sort.Slice(chirpSlice, func(i, j int) bool { return chirpSlice[i].Id < chirpSlice[j].Id })
	writeData, err := json.Marshal(chirpSlice)
	if err != nil {
		respondWithError(w, "Error writing response")
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(writeData)
}

func (apiCfg *apiConfig) getChirp(w http.ResponseWriter, r *http.Request) {

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

	strId := r.PathValue("chirpID")
	id, err := strconv.Atoi(strId)
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
