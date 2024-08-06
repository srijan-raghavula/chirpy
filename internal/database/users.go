package database

import (
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/srijan-raghavula/chirpy/internal/secret"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
	"strconv"
	"time"
)

type User struct {
	Id           int    `json:"id"`
	Email        string `json:"email"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    time.Time
}

type UserLogin struct {
	Email     string        `json:"email"`
	Id        int           `json:"id"`
	ExpiresIn time.Duration `json:"expires_in_seconds"`
}

type authenticatedUser struct {
	Email        string `json:"email"`
	Id           int    `json:"id"`
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
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
	if _, ok := dataJSON.Users[userId]; !ok {
		return User{}, errors.New("User doesn't exist")
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

func (dbPath *DBPath) getUserByToken(token string) (User, bool, error) {
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
		if token == v.RefreshToken {
			return v, true, nil
		}
	}
	return User{}, false, nil
}

func (dbPath *DBPath) ValidateToken(token string) (bool, int, error) {
	user, exist, err := dbPath.getUserByToken(token)
	if err != nil {
		return false, 0, err
	}
	if !exist {
		return false, 0, nil
	}
	if time.Now().UTC().After(user.ExpiresAt) {
		return false, 0, nil
	}

	return true, user.Id, nil
}

func (dbPath DBPath) AuthUser(email string, password []byte, jwtSecret string, expiresIn int) (authenticatedUser, bool, error) {
	log.Println("auth user called")
	dbPath.Mu.RLock()
	defer dbPath.Mu.RUnlock()

	userGeneral, exists, err := dbPath.getUserByEmail(email)
	log.Println("got user info")
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
	log.Println("got token")
	if err != nil {
		return user, false, err
	}
	user.RefreshToken, err = secret.GetRefreshToken()
	log.Println("got refresh token")
	if err != nil {
		return user, false, err
	}
	log.Println("adding token")
	err = dbPath.AddToken(user.Id, user.RefreshToken)
	log.Println("token added to db")
	if err != nil {
		return user, false, nil
	}

	return user, true, nil
}

func (dbPath *DBPath) UpdateUser(token *jwt.Token, newCreds Creds) (User, error) {
	dbPath.Mu.RLock()
	defer dbPath.Mu.RUnlock()

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

	dbFile, err := os.Create("database.json")
	if err != nil {
		return User{}, errors.New("Failed to create a file")
	}

	data, err = json.Marshal(db)
	if err != nil {
		return User{}, err
	}

	_, err = dbFile.Write(data)
	if err != nil {
		return User{}, errors.New("Error updating database")
	}

	return dbPath.GetUser(userId)
}

func (dbPath *DBPath) AddToken(userId int, token string) error {
	log.Println("received call to addtoken")
	dbPath.Mu.Lock()
	defer dbPath.Mu.Unlock()
	log.Println("adding token")

	data, err := os.ReadFile(dbPath.Path)
	if err != nil {
		return err
	}

	var db DBStructure
	err = json.Unmarshal(data, &db)
	if err != nil {
		return err
	}

	user := db.Users[userId]
	user.RefreshToken = token
	user.ExpiresAt = time.Now().UTC().Add(60 * 3600 * time.Second)
	db.Users[userId] = user

	dbFile, err := os.Create(dbPath.Path)
	if err != nil {
		return err
	}

	data, err = json.Marshal(db)
	if err != nil {
		return err
	}

	_, err = dbFile.Write(data)
	if err != nil {
		return errors.New("Error updating database")
	}
	log.Println("token added")

	return nil
}

func (dbPath *DBPath) RemoveToken(token string) error {
	dbPath.Mu.Lock()
	defer dbPath.Mu.Unlock()

	user, exist, err := dbPath.getUserByToken(token)
	if err != nil {
		return err
	}
	if !exist {
		return errors.New("user doesn't exist")
	}

	var db DBStructure
	data, err := os.ReadFile(dbPath.Path)
	if err != nil {
		return err
	}
	json.Unmarshal(data, &db)

	user.RefreshToken = ""
	db.Users[user.Id] = user

	dbFile, err := os.Create(dbPath.Path)
	if err != nil {
		return err
	}

	data, err = json.Marshal(db)
	if err != nil {
		return err
	}

	_, err = dbFile.Write(data)
	if err != nil {
		return errors.New("Error updating database")
	}

	return nil
}
