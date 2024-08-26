package main

import (
	"net/http"
)

func (cfg *apiConfig) handlePolkaHooks(w http.ResponseWriter, req *http.Request) {
	type hook struct {
		Event string `json:"event"`
		Data  struct {
			UserID int `json:"user_id"`
		} `json:"data"`
	}
	hookData := hook{}
	dErr := decodeJSONBody(req, &hookData)
	if dErr != nil {
		respondWithError(w, http.StatusBadRequest, "Wrong format")
		return
	}

	if hookData.Event != "user.upgraded" {
		respondWithoutContent(w, http.StatusNoContent)
		return
	}

	if uErr := cfg.db.UpgradeUser(hookData.Data.UserID); uErr != nil {
		respondWithoutContent(w, http.StatusNotFound)
		return
	}
	respondWithoutContent(w, http.StatusNoContent)
	return
}
