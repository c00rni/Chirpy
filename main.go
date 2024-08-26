package main

import (
	"github.com/c00rni/chirpy/internal/database"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"os"
)

type apiConfig struct {
	fileserverHits int
	port           string
	chirpId        int
	db             *database.DB
	jwtSecret      string
}

func (cfg *apiConfig) handlerReset(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits = 0
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits reset to 0"))
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		w.Header().Set("Cache-Control", "no-cache")
		next.ServeHTTP(w, r)
	})
}

func main() {
	mux := http.NewServeMux()
	const filepathRoot = "."
	const databasePath = "database.json"
	connexion, dbErr := database.NewDB(databasePath)
	if dbErr != nil {
		log.Fatalf("Error: %v", dbErr)
		return
	}
	defer os.Remove(databasePath)

	godotenv.Load()
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatalln("'JWT_SECRET' not set, define a .env with a secret to start.")
		return
	}
	apiCfg := apiConfig{
		fileserverHits: 0,
		port:           "8080",
		db:             connexion,
		jwtSecret:      jwtSecret,
	}

	mux.Handle("GET /app/*", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))))
	mux.HandleFunc("/admin/metrics", apiCfg.handlerAdminMetrics)
	mux.HandleFunc("GET /api/reset", apiCfg.handlerReset)
	mux.HandleFunc("GET /api/healthz", handlReadyness)
	mux.HandleFunc("POST /api/chirps", apiCfg.handlerValidation)
	mux.HandleFunc("GET /api/chirps", apiCfg.listChirps)
	mux.HandleFunc("GET /api/chirps/{id}", apiCfg.getChirps)
	mux.HandleFunc("POST /api/users", apiCfg.handlerUser)
	mux.HandleFunc("POST /api/login", apiCfg.handleAuth)
	mux.HandleFunc("PUT /api/users", apiCfg.updatePasswordHandle)
	mux.HandleFunc("POST /api/refresh", apiCfg.handleRefreshToken)
	mux.HandleFunc("POST /api/revoke", apiCfg.handleRevoke)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.handleChirpDelete)

	srv := &http.Server{
		Handler: mux,
		Addr:    "localhost:" + apiCfg.port,
	}

	log.Printf("Serving on port: %s\n", apiCfg.port)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal("Error: w%", err)
	}
}
