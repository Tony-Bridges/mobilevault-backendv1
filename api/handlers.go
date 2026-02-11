package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Tony-Bridges/mobilevault-backendv1/models"
	"github.com/gorilla/mux"
)

func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	var req models.CreateSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate request
	if req.DeviceID == "" {
		writeError(w, http.StatusBadRequest, "Device ID is required")
		return
	}

	response, err := s.orchestrator.CreateSession(r.Context(), &req, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, response)
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]
	userID := r.Context().Value("user_id").(string)

	// Get session from database
	session, err := s.db.GetVMSession(r.Context(), sessionID)
	if err != nil {
		writeError(w, http.StatusNotFound, "Session not found")
		return
	}

	// Verify ownership
	if session.UserID != userID {
		writeError(w, http.StatusForbidden, "Access denied")
		return
	}

	writeJSON(w, http.StatusOK, session)
}

func (s *Server) terminateSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]
	userID := r.Context().Value("user_id").(string)

	// Verify ownership first
	session, err := s.db.GetVMSession(r.Context(), sessionID)
	if err != nil || session.UserID != userID {
		writeError(w, http.StatusForbidden, "Access denied")
		return
	}

	if err := s.orchestrator.TerminateSession(r.Context(), sessionID, userID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "terminated"})
}

func (s *Server) getDevices(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	devices, err := s.db.GetUserDevices(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, devices)
}

func (s *Server) createDevice(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	var device models.Device
	if err := json.NewDecoder(r.Body).Decode(&device); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Set user ID and generate device ID
	device.UserID = userID
	device.ID = generateUUID()
	device.IsActive = true
	device.CreatedAt = time.Now()

	if err := s.db.CreateDevice(r.Context(), &device); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, device)
}

func (s *Server) getSnapshots(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	snapshots, err := s.db.GetUserSnapshots(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, snapshots)
}

// Helper functions
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
