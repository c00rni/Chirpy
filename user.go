package main

import (
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strconv"
	"time"
)

func (cfg *apiConfig) handlerUser(w http.ResponseWriter, req *http.Request) {
	type response struct {
		Id    int    `json:"id"`
		Email string `json:"email"`
	}

	type credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	userData := credentials{}
	if err := decodeJSONBody(req, &userData); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Bad input data")
		return
	}

	hashedPassword, decryptErr := bcryptHashedPassword(w, userData.Password)
	if decryptErr != nil {
		respondWithError(w, http.StatusBadRequest, "Password too long")
		return
	}

	user, dbErr := cfg.db.CreateUser(userData.Email, hashedPassword)
	if dbErr != nil {
		log.Printf("Failed to get data : %v", dbErr)
		respondWithError(w, http.StatusInternalServerError, "User not registered")
		return
	}

	sErr := respondWithJSON(w, http.StatusCreated, response{Id: user.Id, Email: user.Email})
	if sErr != nil {
		log.Printf("Failed to read data : %s", sErr)
		return
	}
}

// HandleAuth verify the user credential with the database send back the matching id and email
func (cfg *apiConfig) handleAuth(w http.ResponseWriter, req *http.Request) {
	type requestInput struct {
		Email              string `json:"email"`
		Password           string `json:"password"`
		Expires_in_seconds int    `json:"expires_in_seconds"`
	}

	type response struct {
		Id    int    `json:"id"`
		Email string `json:"email"`
		Token string `json:"token"`
	}

	userData := requestInput{}
	err := decodeJSONBody(req, &userData)
	if err != nil {
		log.Printf("Failed to decode user input : %v", err)
		respondWithError(w, http.StatusInternalServerError, "Bad input data")
		return
	}

	allDb, dErr := cfg.db.LoadDB()
	if dErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	for _, user := range allDb.Users {
		if err := bcrypt.CompareHashAndPassword(user.Password, []byte(userData.Password)); err == nil && user.Email == userData.Email {

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

			jwtToken, cErr := createJWT(claims, jwt.SigningMethodHS256, []byte(cfg.jwtSecret))
			if cErr != nil {
				log.Printf("Error %v", cErr)
				respondWithError(w, http.StatusInternalServerError, "Internal Error")
				return
			}
			respondWithJSON(w, http.StatusOK, response{Id: user.Id, Email: user.Email, Token: jwtToken})
			return
		}
	}
	respondWithError(w, http.StatusUnauthorized, "Unauthorized")
	return
}

func (cfg *apiConfig) updatePasswordHandle(w http.ResponseWriter, req *http.Request) {
	type response struct {
		Id    int    `json:"id"`
		Email string `json:"email"`
	}

	type credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	tokenStr := extractJWT(req)
	vErr := verifyToken(tokenStr, []byte(cfg.jwtSecret), "chirpy")
	if vErr != nil {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized token")
		return
	}

	userData := credentials{}
	dErr := decodeJSONBody(req, &userData)
	if dErr != nil {
		respondWithError(w, http.StatusBadRequest, "Internal Error")
		return
	}

	hashedPassword, hErr := bcryptHashedPassword(w, userData.Password)
	if hErr != nil {
		log.Printf("Failed to cipher a password")
		respondWithError(w, http.StatusBadRequest, "Failed to cipher password")
		return
	}

	suject, sErr := getTokenSubject(tokenStr, []byte(cfg.jwtSecret))
	if sErr != nil {
		respondWithError(w, http.StatusBadRequest, "Bad authentication token")
	}
	userId, _ := strconv.Atoi(suject)

	modifiedUser, uErr := cfg.db.UpdateUser(userId, userData.Email, hashedPassword)
	if uErr != nil {
		log.Printf("Error while update: %v", uErr)
		return
	}

	err3 := respondWithJSON(w, http.StatusOK, response{Id: userId, Email: modifiedUser.Email})
	if err3 != nil {
		respondWithError(w, http.StatusInternalServerError, "Internal error")
		return
	}
}
