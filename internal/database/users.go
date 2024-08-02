package database

import (
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/srijan-raghavula/chirpy/internal/secret"
	"golang.org/x/crypto/bcrypt"
	"os"
	"strconv"
	"time"
)

type User struct {
	Id    int    `json:"id"`
	Email string `json:"email"`
}

type UserLogin struct {
	Email     string        `json:"email"`
	Id        int           `json:"id"`
	ExpiresIn time.Duration `json:"expires_in_seconds"`
}

type authenticatedUser struct {
	Email string `json:"email"`
	Id    int    `json:"id"`
	Token string `json:"token"`
}

type UserPassword struct {
	Id       int    `json:"id"`
	Password []byte `json:"password"`
}

type Creds struct {
	Id       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (dbPath *DBPath) AddUser(user User, password UserPassword) error {
	dbPath.Mu.Lock()
	defer dbPath.Mu.Unlock()

	_, err := os.Stat(dbPath.Path)
	if err != nil {
		dbFile, err := os.Create("database.json")
		if err != nil {
			return errors.New("Failed to create a file")
		}

		db := DBStructure{
			Chirps: map[int]Chirp{},
			Users: map[int]User{
				user.Id: user,
			},
			Passwords: map[int]UserPassword{
				user.Id: {
					Id:       password.Id,
					Password: password.Password,
				},
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

	_, exists, err := dbPath.getUserByEmail(user.Email)
	if err != nil {
		return err
	}
	if exists {
		return errors.New("User exists")
	}

	dataJSON.Users[user.Id] = user
	dataJSON.Passwords[user.Id] = password

	dbFile, err := os.Create("database.json")
	if err != nil {
		return errors.New("Failed to create a file")
	}

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

func (dbPath *DBPath) GetUser(userId int) (User, error) {
	dbPath.Mu.RLock()
	defer dbPath.Mu.RUnlock()

	_, err := os.Stat(dbPath.Path)
	if err != nil {
		return User{}, errors.New("File doesn't exist")
	}

	data, err := os.ReadFile(dbPath.Path)
	if err != nil {
		return User{}, errors.New("Error reading database")
	}
	var dataJSON DBStructure
	err = json.Unmarshal(data, &dataJSON)
	if err != nil {
		return User{}, errors.New("Error unmarshaling data")
	}

	return dataJSON.Users[userId], nil
}

func (dbPath *DBPath) getUserByEmail(email string) (User, bool, error) {
	dbPath.Mu.RLock()
	defer dbPath.Mu.RUnlock()
	var db DBStructure

	data, err := os.ReadFile(dbPath.Path)
	if err != nil {
		return User{}, false, err
	}
	err = json.Unmarshal(data, &db)
	if err != nil {
		return User{}, false, err
	}

	idUserMap := db.Users
	for _, v := range idUserMap {
		if email == v.Email {
			return v, true, nil
		}
	}
	return User{}, false, nil
}

func (dbPath DBPath) AuthUser(email string, password []byte, jwtSecret string, expiresIn int) (authenticatedUser, bool, error) {
	userGeneral, exists, err := dbPath.getUserByEmail(email)
	user := authenticatedUser{
		Email: userGeneral.Email,
		Id:    userGeneral.Id,
	}
	if err != nil {
		return user, false, err
	}
	if !exists {
		return user, false, errors.New("user doesn't exist")
	}

	var db DBStructure
	data, err := os.ReadFile(dbPath.Path)
	if err != nil {
		return user, false, err
	}
	json.Unmarshal(data, &db)

	pwdMap := db.Passwords

	err = bcrypt.CompareHashAndPassword(pwdMap[user.Id].Password, password)
	if err != nil {
		return authenticatedUser{}, false, nil
	}

	user.Token, err = secret.GetToken(user.Id, time.Duration(expiresIn), jwtSecret)
	if err != nil {
		return user, false, err
	}

	return user, true, nil
}

func (dbPath *DBPath) UpdateUser(token *jwt.Token, newCreds Creds) (User, error) {
	var updatedUser User

	userIdStr, err := token.Claims.GetSubject()
	if err != nil {
		return updatedUser, err
	}

	userId, err := strconv.Atoi(userIdStr)
	if err != nil {
		return updatedUser, err
	}

	var db DBStructure
	data, err := os.ReadFile(dbPath.Path)
	if err != nil {
		return updatedUser, err
	}
	json.Unmarshal(data, &db)

	// update the old user with new email
	oldUser := db.Users[userId]
	oldUser.Email = newCreds.Email
	db.Users[userId] = oldUser

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(newCreds.Password), bcrypt.DefaultCost)
	if err != nil {
		return updatedUser, err
	}

	// update old password with new hash
	oldPassword := db.Passwords[userId]
	oldPassword.Password = passwordHash
	db.Passwords[userId] = oldPassword

	updatedUser, err = dbPath.GetUser(userId)

	return updatedUser, err
}
