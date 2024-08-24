package main

import (
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type loginInput struct {
	Email              string `json:"email"`
	Password           string `json:"password"`
	Expires_in_seconds int    `json:"expires_in_seconds"`
}

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type responseWithToken struct {
	Id    int    `json:"id"`
	Email string `json:"email"`
	Token string `json:"token"`
}

func (cfg *apiConfig) handlerUser(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	decoder := json.NewDecoder(req.Body)
	userData := credentials{}
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

	type response struct {
		Id    int    `json:"id"`
		Email string `json:"email"`
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
	userData := loginInput{}
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

			const dayDuration = 60 * 60 * 24
			var expirationTime time.Duration = time.Second * time.Duration(userData.Expires_in_seconds)
			if userData.Expires_in_seconds == 0 || userData.Expires_in_seconds > dayDuration {
				expirationTime = time.Hour * 24
			}

			// Create the Claims
			claims := &jwt.RegisteredClaims{
				Issuer:    "chirpy",
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate((time.Now()).Add(expirationTime)),
				Subject:   strconv.Itoa(user.Id),
			}

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			ss, sErr := token.SignedString([]byte(cfg.jwtSecret))
			if sErr != nil {
				log.Printf("Failed to generate a token : %v", sErr)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusOK)
			bodyRes, _ := json.Marshal(responseWithToken{Id: user.Id, Email: user.Email, Token: ss})
			w.Write(bodyRes)
			return
		}
	}
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte{})
	return
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) error {
	response, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
	return nil
}

func (cfg *apiConfig) updatePasswordHandle(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenHeader := req.Header.Get("Authorization")
	tokenStr := strings.TrimPrefix(tokenHeader, "Bearer ")
	token, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.jwtSecret), nil
	})
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte{})
		return
	}
	idStr, err1 := token.Claims.GetSubject()
	if err1 != nil {
		w.WriteHeader(http.StatusUnauthorized)
		log.Printf("Fatal2 error: %v", err1)
		return
	}
	userId, err2 := strconv.Atoi(idStr)
	if err2 != nil {
		log.Printf("Fatal3 error: %v", err2)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	decoder := json.NewDecoder(req.Body)
	userData := credentials{}
	dErr := decoder.Decode(&userData)
	if dErr != nil {
		log.Printf("Failed to decode user input : %v", dErr)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	inputPass := userData.Password

	bytePassword := []byte(inputPass)
	if len(bytePassword) > 72 {
		log.Printf("Password to long")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	hashedPassword, hErr := bcrypt.GenerateFromPassword(bytePassword, bcrypt.DefaultCost)
	if hErr != nil {
		log.Printf("Failed to cipher a password")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	modifiedUser, uErr := cfg.db.UpdateUser(userId, userData.Email, hashedPassword)
	if uErr != nil {
		log.Printf("Error while update: %v", uErr)
		return
	}
	type response struct {
		Id    int    `json:"id"`
		Email string `json:"email"`
	}
	bodyRes, err3 := json.Marshal(response{Id: userId, Email: modifiedUser.Email})
	if err3 != nil {
		log.Printf("Fatal error: %v", err3)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(bodyRes)
}
