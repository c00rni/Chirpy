package main

import (
	"net/http"
)

func handlReadyness(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-9")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
