package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strings"
)

func decodeJSONBody(r *http.Request, ptr interface{}) error {
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(ptr)
	if err != nil {
		return errors.New("Failed to extact data from the request")
	}
	return nil
}

func createJWT(claims *jwt.RegisteredClaims, signingMethod jwt.SigningMethod, secret []byte) (string, error) {
	token := jwt.NewWithClaims(signingMethod, claims)
	jwtToken, sErr := token.SignedString(secret)
	if sErr != nil {
		return "", sErr
	}
	return jwtToken, nil
}

func generateRefreshToken() (string, error) {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	if err != nil {
		return "", errors.New("Failed to create the refreshToken")
	}
	return hex.EncodeToString(randBytes), nil
}

func respondWithoutContent(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
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

func respondWithError(w http.ResponseWriter, code int, errorMessage string) error {
	type response struct {
		Error string `json:"error"`
	}

	return respondWithJSON(w, code, response{Error: errorMessage})
}

func bcryptHashedPassword(w http.ResponseWriter, password string) ([]byte, error) {
	bytePassword := []byte(password)
	hashedPassword, hErr := bcrypt.GenerateFromPassword(bytePassword, bcrypt.DefaultCost)
	if hErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return []byte{}, errors.New("Failed to cipher the password. The password is too long.")
	}
	return hashedPassword, nil
}

func verifyToken(tokenString string, secret []byte, issuerName string) error {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	error := errors.New("Unauthorized token")
	if err != nil {
		return error
	}
	_, err1 := token.Claims.GetSubject()
	if err1 != nil {
		return error
	}

	issuer, err2 := token.Claims.GetIssuer()
	if err2 != nil {
		return error
	}

	if issuer != issuerName {
		return error
	}

	return nil
}

func getTokenSubject(tokenString string, secret []byte) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	error := errors.New("Unauthorized token")
	if err != nil {
		return "", error
	}
	subject, err1 := token.Claims.GetSubject()
	if err1 != nil {
		return "", error
	}
	return subject, nil
}

func extractJWT(r *http.Request) string {
	tokenHeader := r.Header.Get("Authorization")
	return strings.TrimPrefix(tokenHeader, "Bearer ")
}

func extractApiKey(r *http.Request) string {
	tokenHeader := r.Header.Get("Authorization")
	return strings.TrimPrefix(tokenHeader, "ApiKey ")
}

func getPathValue(r *http.Request, param string) string {
	return r.PathValue(param)
}
