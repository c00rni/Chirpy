package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func (cfg *apiConfig) handlerValidation(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	type userInput struct {
		Body string `json:"body"`
	}
	type errorRes struct {
		Error string `json:"error"`
	}
	defer req.Body.Close()

	token := extractJWT(req)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	decoder := json.NewDecoder(req.Body)
	userData := userInput{}
	err := decoder.Decode(&userData)
	if err != nil {
		log.Printf("Error decoding userInput: %s", err)
		w.WriteHeader(500)
		return
	}

	if len(userData.Body) > 140 {
		w.WriteHeader(http.StatusBadRequest)
		errMsg := errorRes{
			Error: "Chirp is too long",
		}
		data, er := json.Marshal(errMsg)
		if er != nil {
			log.Printf("Error: %s", er)
		}
		w.Write(data)
		return
	}

	if userData.Body == "" {
		w.WriteHeader(http.StatusBadRequest)
		errMsg := errorRes{
			Error: "The body is empty",
		}
		data, er := json.Marshal(errMsg)
		if er != nil {
			log.Printf("Error: %s", er)
		}
		w.Write(data)
		return
	}

	words := strings.Split(userData.Body, " ")
	cleanedW := make([]string, 0)
	badWord := map[string]bool{"kerfuffle": true, "sharbert": true, "fornax": true}
	for _, word := range words {
		if _, ok := badWord[strings.ToLower(word)]; !ok {
			cleanedW = append(cleanedW, word)
			continue
		}
		cleanedW = append(cleanedW, "****")
	}
	cleanedStr := strings.Join(cleanedW, " ")

	subject, sErr := getTokenSubject(token, []byte(cfg.jwtSecret))
	if sErr != nil {
		respondWithError(w, http.StatusUnauthorized, "Unautohorized token")
		return
	}
	userId, iErr := strconv.Atoi(subject)
	if iErr != nil {
		respondWithError(w, http.StatusUnauthorized, "Unautohorized token")
		return
	}
	chirp, cErr := cfg.db.CreateChirp(cleanedStr, userId)
	if cErr != nil {
		log.Printf("Failed to create chirp : %v", cErr)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte{})
		return
	}

	data, er := json.Marshal(chirp)
	if er != nil {
		log.Printf("Failed to encode data : %s", er)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte{})
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write(data)
}

func (cfg *apiConfig) handleChirpDelete(w http.ResponseWriter, req *http.Request) {
	token := extractJWT(req)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	subject, sErr := getTokenSubject(token, []byte(cfg.jwtSecret))
	if sErr != nil {
		respondWithError(w, http.StatusUnauthorized, "Unautohorized token")
		return
	}
	userId, iErr := strconv.Atoi(subject)
	if iErr != nil {
		respondWithError(w, http.StatusUnauthorized, "Unautohorized token")
		return
	}

	idStr := getPathValue(req, "chirpID")
	chirpId, cErr := strconv.Atoi(idStr)
	if cErr != nil {
		respondWithError(w, http.StatusInternalServerError, "Internal error")
		return
	}

	dErr := cfg.db.DeleteChirp(chirpId, userId)
	if dErr != nil {
		respondWithError(w, http.StatusForbidden, "Forbidden delete.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
	w.Write([]byte{})
	return
}

func (cfg *apiConfig) listChirps(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authorIdStr := req.URL.Query().Get("author_id")
	authorId, aErr := strconv.Atoi(authorIdStr)
	if authorIdStr != "" && aErr != nil {
		respondWithError(w, http.StatusInternalServerError, "Internal error")
	}
	sortDirection := req.URL.Query().Get("sort")
	if sortDirection != "desc" {
		sortDirection = "asc"
	}
	if authorIdStr == "" {
		chirps, dbErr := cfg.db.GetChirps(sortDirection)
		if dbErr != nil {
			log.Printf("Failed to get data : %v", dbErr)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte{})
			return
		}
		data, er := json.Marshal(chirps)
		if er != nil {
			log.Printf("Failed to read data : %s", er)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte{})
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	} else {
		chirps, dbErr := cfg.db.GetChirps(sortDirection, authorId)
		if dbErr != nil {
			log.Printf("Failed to get data : %v", dbErr)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte{})
			return
		}
		data, er := json.Marshal(chirps)
		if er != nil {
			log.Printf("Failed to read data : %s", er)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte{})
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}
	return
}

func (cfg *apiConfig) getChirps(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	allDb, dbErr := cfg.db.LoadDB()
	if dbErr != nil {
		log.Printf("Failed to get data : %v", dbErr)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte{})
		return
	}
	idStr := getPathValue(r, "id")
	id, cErr := strconv.Atoi(idStr)
	if cErr != nil {
		respondWithError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if chirp, ok := allDb.Chirps[id]; ok {
		data, er := json.Marshal(chirp)
		if er != nil {
			log.Printf("Failed to read data : %s", er)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte{})
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(data)
		return
	}
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte{})
}
