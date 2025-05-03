package main

import (
	"chirpy/internal/auth"
	"chirpy/internal/database"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	jwtSecret      string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

// Utility function for sending JSON responses
func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("Failed to write JSON response: %v", err)
	}
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func sanitizeChirp(input string) string {
	words := strings.Fields(input)
	profanities := map[string]struct{}{
		"kerfuffle": {},
		"sharbert":  {},
		"fornax":    {},
	}

	for i, word := range words {
		if _, found := profanities[strings.ToLower(word)]; found {
			words[i] = "****"
		}
	}
	return strings.Join(words, " ")
}

func validateChirpHandler(w http.ResponseWriter, r *http.Request) {
	type ChirpParams struct {
		// these tags indicate how the keys in the JSON should be mapped to the struct fields
		// the struct fields must be exported (start with a capital letter) if you want them parsed
		Body string `json:"body"`
	}

	type ErrorResponse struct {
		Error string `json:"error"`
	}

	type CleanedResponse struct {
		CleanedBody string `json:"cleaned_body"`
	}

	var params ChirpParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		log.Printf("Error decoding JSON: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Something went wrong"})
		return
	}

}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write([]byte(fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())))
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)
	cfg.db.ResetUser(r.Context())

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("Reset counter!"))
}

func (cfg *apiConfig) createUserHandler(w http.ResponseWriter, r *http.Request) {
	type UserParams struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type ErrorResponse struct {
		Error string `json:"error"`
	}

	type UserResponse struct {
		ID        string `json:"id"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
		Email     string `json:"email"`
	}

	var params UserParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		log.Printf("Error decoding JSON: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Something went wrong"})
		return
	}

	hashed, err := auth.HashPassword(params.Password)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Something went wrong"})
		return
	}

	// Now pass the sql.NullString to CreateUser
	user, err := cfg.db.CreateUser(r.Context(), database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hashed,
	})
	if err != nil {
		log.Printf("Error creating user: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Could not create user"})
		return
	}

	response := UserResponse{
		ID:        user.ID.String(),
		Email:     user.Email,
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
		UpdatedAt: user.UpdatedAt.Format(time.RFC3339),
	}

	writeJSON(w, http.StatusCreated, response)
}

func (cfg *apiConfig) updateUserHandler(w http.ResponseWriter, r *http.Request) {
	type UserParams struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type ErrorResponse struct {
		Error string `json:"error"`
	}

	type UserResponse struct {
		ID        string `json:"id"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
		Email     string `json:"email"`
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error getting Bearer Token: %v", err)
		writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "Error getting Bearer Token"})
		return
	}

	var params UserParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		log.Printf("Error decoding JSON: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Something went wrong"})
		return
	}

	hashed, err := auth.HashPassword(params.Password)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Something went wrong"})
		return
	}

	userUuid, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		log.Printf("Invalid Bearer Token: %v", err)
		writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "Invalid Bearer Token"})
		return
	}

	user, err := cfg.db.UpdateUserData(r.Context(), database.UpdateUserDataParams{
		Email:          params.Email,
		HashedPassword: hashed,
		ID:             userUuid,
	})
	if err != nil {
		log.Printf("Error updating user: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Could not update user"})
		return
	}

	response := UserResponse{
		ID:        user.ID.String(),
		Email:     user.Email,
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
		UpdatedAt: user.UpdatedAt.Format(time.RFC3339),
	}

	writeJSON(w, http.StatusOK, response)
}

func (cfg *apiConfig) postChirpHandler(w http.ResponseWriter, r *http.Request) {
	type ChirpParams struct {
		Body string `json:"body"`
	}

	type ErrorResponse struct {
		Error string `json:"error"`
	}

	type ChirpResponse struct {
		ID        string `json:"id"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
		Body      string `json:"body"`
		UserID    string `json:"user_id"`
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error getting Bearer Token: %v", err)
		writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "Error getting Bearer Token"})
		return
	}

	userUuid, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		log.Printf("Invalid Bearer Token: %v", err)
		writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "Invalid Bearer Token"})
		return
	}

	var params ChirpParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		log.Printf("Error decoding JSON: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Something went wrong"})
		return
	}

	if len(params.Body) > 140 {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Chirp is too long"})
		return
	}

	cleaned := sanitizeChirp(params.Body)

	chirp, err := cfg.db.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   cleaned,
		UserID: userUuid,
	})
	if err != nil {
		log.Printf("Error creating chirp: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Could not create user"})
		return
	}

	response := ChirpResponse{
		ID:        chirp.ID.String(),
		Body:      chirp.Body,
		UserID:    chirp.UserID.String(),
		CreatedAt: chirp.CreatedAt.Format(time.RFC3339),
		UpdatedAt: chirp.UpdatedAt.Format(time.RFC3339),
	}

	writeJSON(w, http.StatusCreated, response)
}

func (cfg *apiConfig) getAllChirpsHandler(w http.ResponseWriter, r *http.Request) {
	type ChirpResponse struct {
		ID        string `json:"id"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
		Body      string `json:"body"`
		UserID    string `json:"user_id"`
	}

	type ErrorResponse struct {
		Error string `json:"error"`
	}

	chirps, err := cfg.db.GetAllChirps(r.Context()) // returns []Chirp
	if err != nil {
		log.Printf("Error getting chirps: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Could not create user"})
		return
	}

	var responses []ChirpResponse

	for _, chirp := range chirps {
		responses = append(responses, ChirpResponse{
			ID:        chirp.ID.String(),
			Body:      chirp.Body,
			UserID:    chirp.UserID.String(),
			CreatedAt: chirp.CreatedAt.Format(time.RFC3339),
			UpdatedAt: chirp.UpdatedAt.Format(time.RFC3339),
		})
	}

	// Finally, write JSON array
	writeJSON(w, http.StatusOK, responses)
}

func (cfg *apiConfig) getSingleChirpHandler(w http.ResponseWriter, r *http.Request) {
	type ChirpResponse struct {
		ID        string `json:"id"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
		Body      string `json:"body"`
		UserID    string `json:"user_id"`
	}

	type ErrorResponse struct {
		Error string `json:"error"`
	}

	parsedUUID, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid UUID"})
		return
	}

	chirp, err := cfg.db.GetSingleChirp(r.Context(), parsedUUID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// No chirp found
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Chirp not found"})
			return
		}

		// Other DB error
		log.Printf("Error getting chirp: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Internal server error"})
		return
	}

	response := ChirpResponse{
		ID:        chirp.ID.String(),
		Body:      chirp.Body,
		UserID:    chirp.UserID.String(),
		CreatedAt: chirp.CreatedAt.Format(time.RFC3339),
		UpdatedAt: chirp.UpdatedAt.Format(time.RFC3339),
	}

	// Finally, write JSON array
	writeJSON(w, http.StatusOK, response)
}

func (cfg *apiConfig) deleteSingleChirpHandler(w http.ResponseWriter, r *http.Request) {
	type ErrorResponse struct {
		Error string `json:"error"`
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error getting Bearer Token: %v", err)
		writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "Error getting Bearer Token"})
		return
	}

	userUuid, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		log.Printf("Invalid Bearer Token: %v", err)
		writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "Invalid Bearer Token"})
		return
	}

	chirpUuid, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid UUID"})
		return
	}

	chirp, err := cfg.db.GetSingleChirp(r.Context(), chirpUuid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// No chirp found
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Chirp not found"})
			return
		}

		// Other DB error
		log.Printf("Error getting chirp: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Internal server error"})
		return
	}

	// check if users match
	if chirp.UserID != userUuid {
		writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "User unathorized to delete chirp"})
		return
	}

	err = cfg.db.DeleteSingleChirp(r.Context(), chirpUuid)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Error deleting chirp"})
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, r *http.Request) {
	type UserParams struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type ErrorResponse struct {
		Error string `json:"error"`
	}

	type UserResponse struct {
		ID           string `json:"id"`
		CreatedAt    string `json:"created_at"`
		UpdatedAt    string `json:"updated_at"`
		Email        string `json:"email"`
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}

	var params UserParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		log.Printf("Error decoding JSON: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Something went wrong"})
		return
	}

	user, err := cfg.db.SelectUserByEmail(r.Context(), params.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// No chirp found
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "User not found"})
			return
		}

		// Other DB error
		log.Printf("Error getting user: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Internal server error"})
		return
	}

	if err = auth.CheckPasswordHash(user.HashedPassword, params.Password); err != nil {
		log.Printf("User entered wrong password: %v", err)
		writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "Invalid Credentials"})
		return
	}

	// Generate JWT Token
	expiresIn := time.Hour // Default expiration
	token, err := auth.MakeJWT(user.ID, cfg.jwtSecret, expiresIn)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Could not create token"})
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Could not create refresh token"})
		return
	}

	// generate refresh token
	_, err = cfg.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		UserID: user.ID,
		Token:  refreshToken,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Error saving refresh tokens"})
		return
	}

	response := UserResponse{
		ID:           user.ID.String(),
		Email:        user.Email,
		CreatedAt:    user.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    user.UpdatedAt.Format(time.RFC3339),
		Token:        token,
		RefreshToken: refreshToken,
	}

	writeJSON(w, http.StatusOK, response)
}

func (cfg *apiConfig) refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	type ErrorResponse struct {
		Error string `json:"error"`
	}

	type UserResponse struct {
		Token string `json:"token"`
	}

	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "Error getting bearer token"})
		return
	}

	tokenRow, err := cfg.db.GetSingleRefreshToken(r.Context(), refreshToken)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// No refresh token found
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "Refresh token not found"})
			return
		}

		// Other DB error
		log.Printf("Error getting chirp: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Internal server error"})
		return
	}

	if time.Now().UTC().After(tokenRow.ExpiresAt.UTC()) {
		writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "Refresh token expired"})
		return
	}

	// revokedAt is not null, token was revoked
	if tokenRow.RevokedAt.Valid {
		writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "Refresh token revoked"})
		return
	}

	expiresIn := time.Hour // Default expiration
	accessToken, err := auth.MakeJWT(tokenRow.UserID, cfg.jwtSecret, expiresIn)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Internal server error"})
		return
	}

	writeJSON(w, http.StatusOK, UserResponse{Token: accessToken})
}

func (cfg *apiConfig) revokeTokenHandler(w http.ResponseWriter, r *http.Request) {
	type ErrorResponse struct {
		Error string `json:"error"`
	}

	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "Error getting bearer token"})
		return
	}

	_, err = cfg.db.RevokeRefreshToken(r.Context(), refreshToken)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// No refresh token found
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "Refresh token not found"})
			return
		}

		// Other DB error
		log.Printf("Error getting chirp: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Internal server error"})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	jwtSecret := os.Getenv("JWT_SECRET")

	db, _ := sql.Open("postgres", dbURL)

	dbQueries := database.New(db)

	var cfg apiConfig
	cfg.db = dbQueries
	cfg.jwtSecret = jwtSecret

	mux := http.NewServeMux()

	fileserverHandler := http.StripPrefix("/app", http.FileServer(http.Dir(".")))
	mux.Handle("/app/", cfg.middlewareMetricsInc(fileserverHandler))

	mux.HandleFunc("GET /api/healthz", healthzHandler)
	mux.HandleFunc("POST /api/validate_chirp", validateChirpHandler)

	mux.HandleFunc("POST /api/users", cfg.createUserHandler)
	mux.HandleFunc("PUT /api/users", cfg.updateUserHandler)

	mux.HandleFunc("POST /api/chirps", cfg.postChirpHandler)
	mux.HandleFunc("GET /api/chirps", cfg.getAllChirpsHandler)
	mux.HandleFunc("GET /api/chirps/{chirpID}", cfg.getSingleChirpHandler)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", cfg.deleteSingleChirpHandler)

	mux.HandleFunc("POST /api/login", cfg.loginHandler)
	mux.HandleFunc("POST /api/refresh", cfg.refreshTokenHandler)
	mux.HandleFunc("POST /api/revoke", cfg.revokeTokenHandler)

	mux.HandleFunc("POST /admin/reset", cfg.resetHandler)
	mux.HandleFunc("GET /admin/metrics", cfg.metricsHandler)

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	server.ListenAndServe()
	fmt.Println("Server listening at port 8080")
}
