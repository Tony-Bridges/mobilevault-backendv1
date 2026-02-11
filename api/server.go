package api

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/yourusername/mobilevault-backend/db"
	"github.com/yourusername/mobilevault-backend/services/orchestrator"
)

type Server struct {
	router        *mux.Router
	db            *db.Database
	orchestrator  *orchestrator.OrchestratorService
	authenticator *Authenticator
}

func NewServer(db *db.Database) *Server {
	router := mux.NewRouter()
	repo := db.NewRepository(db)
	
	server := &Server{
		router:        router,
		db:            db,
		orchestrator:  orchestrator.NewOrchestratorService(repo),
		authenticator: NewAuthenticator(db),
	}

	server.setupRoutes()
	return server
}

func (s *Server) setupRoutes() {
	// Health check
	s.router.HandleFunc("/health", s.healthCheck).Methods("GET")
	
	// Auth routes
	s.router.HandleFunc("/api/v1/auth/register", s.register).Methods("POST")
	s.router.HandleFunc("/api/v1/auth/login", s.login).Methods("POST")
	s.router.HandleFunc("/api/v1/auth/refresh", s.refreshToken).Methods("POST")
	
	// Protected routes
	api := s.router.PathPrefix("/api/v1").Subrouter()
	api.Use(s.authenticator.Middleware)
	
	// Devices
	api.HandleFunc("/devices", s.getDevices).Methods("GET")
	api.HandleFunc("/devices", s.createDevice).Methods("POST")
	api.HandleFunc("/devices/{id}", s.getDevice).Methods("GET")
	api.HandleFunc("/devices/{id}", s.updateDevice).Methods("PUT")
	api.HandleFunc("/devices/{id}", s.deleteDevice).Methods("DELETE")
	
	// Snapshots
	api.HandleFunc("/snapshots", s.getSnapshots).Methods("GET")
	api.HandleFunc("/snapshots", s.createSnapshot).Methods("POST")
	api.HandleFunc("/snapshots/{id}", s.getSnapshot).Methods("GET")
	api.HandleFunc("/snapshots/{id}", s.deleteSnapshot).Methods("DELETE")
	
	// Sessions
	api.HandleFunc("/sessions", s.createSession).Methods("POST")
	api.HandleFunc("/sessions/{id}", s.getSession).Methods("GET")
	api.HandleFunc("/sessions/{id}", s.terminateSession).Methods("DELETE")
	api.HandleFunc("/sessions/{id}/webrtc", s.getWebRTCOffer).Methods("GET")
	
	// Settings
	api.HandleFunc("/settings", s.getSettings).Methods("GET")
	api.HandleFunc("/settings", s.updateSettings).Methods("PUT")
}

func (s *Server) Start() error {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Configure CORS
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"}, // In production, restrict this
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	})

	handler := corsHandler.Handler(s.router)
	
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("🚀 Server starting on port %s", port)
	return server.ListenAndServe()
}

func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request) {
	// Check database connectivity
	ctx := r.Context()
	if err := s.db.Postgres.Ping(ctx); err != nil {
		http.Error(w, "Database not connected", http.StatusServiceUnavailable)
		return
	}

	if err := s.db.Redis.Ping(ctx).Err(); err != nil {
		http.Error(w, "Redis not connected", http.StatusServiceUnavailable)
		return
	}

	response := map[string]string{
		"status": "healthy",
		"time":   time.Now().UTC().Format(time.RFC3339),
	}
	
	writeJSON(w, http.StatusOK, response)
}