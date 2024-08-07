package database

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

type DBPath struct {
	Path string
	Mu   *sync.RWMutex
}

type DBStructure struct {
	Chirps    map[int]Chirp        `json:"chirps"`
	Users     map[int]User         `json:"users"`
	Passwords map[int]UserPassword `json:"password"`
}

type Chirp struct {
	Id       int    `json:"id"`
	AuthorId int    `json:"author_id"`
	Message  string `json:"body"`
}

func (dbPath *DBPath) GetChirps(path string) ([]byte, error) {

	dbPath.Mu.RLock()
	defer dbPath.Mu.RUnlock()

	_, err := os.Stat(dbPath.Path)
	if err != nil {
		return []byte{}, os.ErrNotExist
	}
	data, err := os.ReadFile(dbPath.Path)
	if err != nil {
		return []byte{}, nil
	}

	return data, nil
}

func (dbPath *DBPath) AddChirp(chirp Chirp) error {
	dbPath.Mu.Lock()
	defer dbPath.Mu.Unlock()

	_, err := os.Stat(dbPath.Path)
	if err != nil {
		dbFile, err := os.Create("database.json")
		if err != nil {
			return errors.New("Failed to create a file")
		}
		db := DBStructure{
			Chirps: map[int]Chirp{
				chirp.Id: chirp,
			},
		}

		data, err := json.Marshal(db)
		if err != nil {
			return err
		}
		_, err = dbFile.Write(data)
		if err != nil {
			return errors.New("Error updating database")
		}
		return nil
	}

	data, err := os.ReadFile("database.json")
	if err != nil {
		return err
	}
	var dataJSON DBStructure
	err = json.Unmarshal(data, &dataJSON)
	if err != nil {
		return err
	}

	dbFile, err := os.Create("database.json")
	if err != nil {
		return errors.New("Failed to create a file")
	}
	dataJSON.Chirps[chirp.Id] = chirp

	data, err = json.Marshal(dataJSON)
	if err != nil {
		return err
	}
	_, err = dbFile.Write(data)
	if err != nil {
		return errors.New("Error updating database")
	}

	return nil
}
