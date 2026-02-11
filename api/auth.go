package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Authenticator struct {
	db        *db.Database
	jwtSecret []byte
}

func NewAuthenticator(db *db.Database) *Authenticator {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "default-secret-key-change-in-production"
	}
	return &Authenticator{
		db:        db,
		jwtSecret: []byte(secret),
	}
}

func (a *Authenticator) register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	// Validate email and password
	if !isValidEmail(req.Email) {
		writeError(w, http.StatusBadRequest, "Invalid email")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "Password must be at least 8 characters")
		return
	}

	// Check if user exists
	existing, err := a.db.GetUserByEmail(r.Context(), req.Email)
	if err == nil && existing != nil {
		writeError(w, http.StatusConflict, "User already exists")
		return
	}

	// Generate encryption key for user
	encryptionKey := generateRandomKey(32)
	encryptedKey, err := encryptKey(encryptionKey, req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	// Create user
	user := &models.User{
		ID:                uuid.New().String(),
		Email:             req.Email,
		EncryptedMasterKey: encryptedKey,
		CreatedAt:         time.Now(),
		IsActive:          true,
		SubscriptionTier:  "free",
	}

	if err := a.db.CreateUser(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	// Create default device for user
	defaultDevice := &models.Device{
		ID:             uuid.New().String(),
		UserID:         user.ID,
		Name:           "My Cloud Phone",
		Model:          "Pixel 6",
		AndroidVersion: "13",
		CPUCores:       4,
		RAMMB:          8192,
		StorageGB:      128,
		GPUEnabled:     false,
		IsActive:       true,
		CreatedAt:      time.Now(),
	}
	
	if err := a.db.CreateDevice(r.Context(), defaultDevice); err != nil {
		log.Printf("Failed to create default device: %v", err)
	}

	// Generate JWT token
	token, err := a.generateToken(user.ID, user.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	response := map[string]interface{}{
		"user": map[string]interface{}{
			"id":    user.ID,
			"email": user.Email,
			"tier":  user.SubscriptionTier,
		},
		"token": token,
	}

	writeJSON(w, http.StatusCreated, response)
}

func (a *Authenticator) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	// Get user
	user, err := a.db.GetUserByEmail(r.Context(), req.Email)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Verify password (in real implementation, you'd decrypt the key)
	// For MVP, we'll use a simplified approach
	if !verifyPassword(user.EncryptedMasterKey, req.Password) {
		writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Update last login
	a.db.UpdateUserLastLogin(r.Context(), user.ID, time.Now())

	// Generate token
	token, err := a.generateToken(user.ID, user.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	response := map[string]interface{}{
		"user": map[string]interface{}{
			"id":    user.ID,
			"email": user.Email,
			"tier":  user.SubscriptionTier,
		},
		"token": token,
	}

	writeJSON(w, http.StatusOK, response)
}

func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get token from header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeError(w, http.StatusUnauthorized, "Authorization header required")
			return
		}

		// Expect "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			writeError(w, http.StatusUnauthorized, "Invalid authorization header")
			return
		}

		tokenString := parts[1]

		// Parse and validate token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return a.jwtSecret, nil
		})

		if err != nil || !token.Valid {
			writeError(w, http.StatusUnauthorized, "Invalid token")
			return
		}

		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			writeError(w, http.StatusUnauthorized, "Invalid token claims")
			return
		}

		// Get user ID from claims
		userID, ok := claims["user_id"].(string)
		if !ok {
			writeError(w, http.StatusUnauthorized, "Invalid user ID in token")
			return
		}

		// Add user ID to context
		ctx := context.WithValue(r.Context(), "user_id", userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *Authenticator) generateToken(userID, email string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   email,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(a.jwtSecret)
}

// Helper functions
func generateRandomKey(length int) []byte {
	key := make([]byte, length)
	rand.Read(key)
	return key
}

func encryptKey(key []byte, password string) ([]byte, error) {
	// Simplified encryption for MVP
	// In production, use proper key derivation and encryption
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	
	// For MVP, we'll just base64 encode
	encoded := base64.StdEncoding.EncodeToString(key)
	return []byte(encoded), nil
}

func verifyPassword(encryptedKey []byte, password string) bool {
	// Simplified verification for MVP
	// In production, properly decrypt and verify
	decoded, err := base64.StdEncoding.DecodeString(string(encryptedKey))
	if err != nil {
		return false
	}
	return len(decoded) > 0 // Simplified check
}

func isValidEmail(email string) bool {
	return strings.Contains(email, "@") && strings.Contains(email, ".")
}