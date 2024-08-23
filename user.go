package main

import (
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
)

type userInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type response struct {
	Id    int    `json:"id"`
	Email string `json:"email"`
}

func (cfg *apiConfig) handlerUser(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	decoder := json.NewDecoder(req.Body)
	userData := userInput{}
	err := decoder.Decode(&userData)
	if err != nil {
		log.Printf("Failed to decode user input : %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	bytePassword := []byte(userData.Password)
	if len(bytePassword) > 72 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	hashedPassword, hErr := bcrypt.GenerateFromPassword(bytePassword, bcrypt.DefaultCost)
	if hErr != nil {
		log.Printf("Failed to cipher a password")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	user, dbErr := cfg.db.CreateUser(userData.Email, hashedPassword)
	if dbErr != nil {
		log.Printf("Failed to get data : %v", dbErr)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte{})
		return
	}
	data, er := json.Marshal(response{Id: user.Id, Email: user.Email})
	if er != nil {
		log.Printf("Failed to read data : %s", er)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte{})
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write(data)
}

// HandleAuth verify the user credential with the database send back the matching id and email
func (cfg *apiConfig) handleAuth(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	decoder := json.NewDecoder(req.Body)
	userData := userInput{}
	err := decoder.Decode(&userData)
	if err != nil {
		log.Printf("Failed to decode user input : %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	inputEmail := userData.Email
	inputPass := userData.Password

	allDb, dErr := cfg.db.LoadDB()
	if dErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	for _, user := range allDb.Users {
		if err := bcrypt.CompareHashAndPassword(user.Password, []byte(inputPass)); err == nil && user.Email == inputEmail {
			w.WriteHeader(http.StatusOK)
			bodyRes, _ := json.Marshal(response{Id: user.Id, Email: user.Email})
			w.Write(bodyRes)
			return
		}
	}
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte{})
	return
}
