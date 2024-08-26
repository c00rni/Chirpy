package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"time"
)

type DB struct {
	path string
	mux  *sync.RWMutex
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users  map[int]User  `json:"users"`
}

type User struct {
	Id              int       `json:"id"`
	Email           string    `json:"email"`
	Password        []byte    `json:"password"`
	RefreshToken    string    `json:"refresh_token"`
	TokenExpiration time.Time `json:"token_expiration"`
	IsRed           bool      `json:"is_chirpy_red"`
}

type Chirp struct {
	Id       int    `json:"id"`
	Body     string `json:"body"`
	AuthorId int    `json:"author_id"`
}

// NewDB creates a new database connection
// and creates the database file if it doesn't exist
func NewDB(path string) (*DB, error) {

	db := DB{
		path: path,
		mux:  &sync.RWMutex{},
	}

	if err := db.ensureDB(); err != nil {
		return &db, err
	}

	return &db, nil
}

// CreateChirp creates a new chirp and saves it to disk
func (db *DB) CreateChirp(body string, userId int) (Chirp, error) {
	database, loadingErr := db.LoadDB()
	if loadingErr != nil {
		return Chirp{}, loadingErr
	}
	id := len(database.Chirps) + 1
	chirp := Chirp{
		Id:       id,
		Body:     body,
		AuthorId: userId,
	}

	database.Chirps[id] = chirp
	if wErr := db.writeDB(database); wErr != nil {
		return Chirp{}, wErr
	}
	return chirp, nil
}

// CreateUser create a new user and save it to disk
func (db *DB) CreateUser(email string, password []byte) (User, error) {
	database, loadingErr := db.LoadDB()
	if loadingErr != nil {
		return User{}, loadingErr
	}
	id := len(database.Users) + 1
	user := User{
		Id:       id,
		Email:    email,
		Password: password,
	}

	database.Users[id] = user
	if wErr := db.writeDB(database); wErr != nil {
		return User{}, wErr
	}
	return user, nil
}

// CreateUser create a new user and save it to disk
func (db *DB) DeleteChirp(chirpId, userId int) error {
	database, loadingErr := db.LoadDB()
	if loadingErr != nil {
		return loadingErr
	}
	if database.Chirps[chirpId].AuthorId != userId {
		return errors.New("Unauthorized delete.")
	}
	delete(database.Chirps, chirpId)
	i := 1
	for _, chirp := range database.Chirps {
		chirp.Id = i
		i += 1
	}
	if wErr := db.writeDB(database); wErr != nil {
		return wErr
	}
	return nil
}

// CreateUser create a new user and save it to disk
func (db *DB) UpgradeUser(userId int) error {
	database, loadingErr := db.LoadDB()
	if loadingErr != nil {
		return loadingErr
	}
	user, ok := database.Users[userId]
	if !ok {
		return errors.New("User do not exist.")
	}
	user.IsRed = true
	database.Users[userId] = user

	if wErr := db.writeDB(database); wErr != nil {
		return wErr
	}
	return nil
}

// UpdateUser update a user info and save it to disk
func (db *DB) UpdateUser(id int, email string, password []byte, refreshToken string) (User, error) {
	database, loadingErr := db.LoadDB()
	if loadingErr != nil {
		return User{}, loadingErr
	}

	if refreshToken == "" {
		refreshToken = database.Users[id].RefreshToken
	}

	user := User{
		Id:              id,
		Email:           email,
		Password:        password,
		RefreshToken:    refreshToken,
		TokenExpiration: time.Now().Add(time.Hour * 24 * 60),
		IsRed:           database.Users[id].IsRed,
	}

	database.Users[id] = user
	if wErr := db.writeDB(database); wErr != nil {
		return User{}, wErr
	}
	return user, nil
}

func (db *DB) GetChirps(sorted string, ids ...int) ([]Chirp, error) {
	database, err := db.LoadDB()
	if err != nil {
		return []Chirp{}, err
	}
	var idMap = make(map[int]bool)
	for i := 0; i < len(ids); i++ {
		idMap[ids[i]] = true
	}
	chirps := []Chirp{}
	if len(ids) == 0 {
		for _, chirp := range database.Chirps {
			chirps = append(chirps, chirp)
		}
	} else {
		for _, chirp := range database.Chirps {
			if _, ok := idMap[chirp.AuthorId]; ok {
				chirps = append(chirps, chirp)
			}
		}
	}
	if sorted == "desc" {
		sort.Slice(chirps, func(i, j int) bool { return chirps[i].Id > chirps[j].Id })
	} else {
		sort.Slice(chirps, func(i, j int) bool { return chirps[i].Id < chirps[j].Id })
	}
	return chirps, nil
}

// ensureDB creates a new database file if it doesn't exist
func (db *DB) ensureDB() error {

	if ok := os.IsNotExist(os.ErrNotExist); ok {
		if err := db.writeDB(DBStructure{Chirps: make(map[int]Chirp), Users: make(map[int]User)}); err != nil {
			return errors.New(fmt.Sprintf("Fail to create the file at %v", err))
		}
		log.Printf("Database created on path %v.", db.path)
	}
	return nil
}

// loadDB reads the database file into memory
func (db *DB) LoadDB() (DBStructure, error) {
	db.mux.RLock()
	var database *DBStructure
	data, rErr := os.ReadFile(db.path)
	if rErr != nil {
		return *database, errors.New(fmt.Sprintf("The file can't be read: %v", data))
	}
	if tErr := json.Unmarshal(data, &database); tErr != nil {
		return *database, errors.New("The database is not formatted properly.")
	}
	db.mux.RUnlock()
	return *database, nil
}

// writeDB writes the database file to disk
func (db *DB) writeDB(dbStructure DBStructure) error {
	db.mux.Lock()
	defer db.mux.Unlock()
	data, _ := json.Marshal(dbStructure)
	if wErr := os.WriteFile(db.path, data, 0644); wErr != nil {
		return wErr
	}
	return nil
}
