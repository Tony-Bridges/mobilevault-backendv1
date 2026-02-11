package main

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "time"

    "github.com/gorilla/mux"
    "github.com/rs/cors"
    _ "github.com/mattn/go-sqlite3"
    "github.com/google/uuid"
    "github.com/golang-jwt/jwt/v5"
)

var db *sql.DB
var jwtSecret = []byte("mobilevault-secret-key-change-in-production")

func main() {
    // Initialize database
    initDB()
    defer db.Close()

    // Create router
    r := mux.NewRouter()

    // Public routes
    r.HandleFunc("/", homeHandler).Methods("GET")
    r.HandleFunc("/health", healthHandler).Methods("GET")
    r.HandleFunc("/api/v1/auth/register", registerHandler).Methods("POST")
    r.HandleFunc("/api/v1/auth/login", loginHandler).Methods("POST")

    // Protected routes
    api := r.PathPrefix("/api/v1").Subrouter()
    api.Use(authMiddleware)
    
    api.HandleFunc("/devices", getDevicesHandler).Methods("GET")
    api.HandleFunc("/devices", createDeviceHandler).Methods("POST")
    api.HandleFunc("/sessions", createSessionHandler).Methods("POST")
    api.HandleFunc("/sessions/{id}", getSessionHandler).Methods("GET")
    api.HandleFunc("/sessions/{id}/terminate", terminateSessionHandler).Methods("POST")

    // Configure CORS
    c := cors.New(cors.Options{
        AllowedOrigins:   []string{"*"},
        AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
        AllowedHeaders:   []string{"Authorization", "Content-Type"},
        AllowCredentials: true,
    })

    handler := c.Handler(r)

    // Start server
    port := "8080"
    if envPort := os.Getenv("PORT"); envPort != "" {
        port = envPort
    }

    log.Printf("🚀 Server starting on http://localhost:%s", port)
    log.Fatal(http.ListenAndServe(":"+port, handler))
}

func initDB() {
    var err error
    db, err = sql.Open("sqlite3", "./mobilevault.db")
    if err != nil {
        log.Fatal(err)
    }

    // Create tables
    createTables := `
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        tier TEXT DEFAULT 'free'
    );

    CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        name TEXT NOT NULL,
        model TEXT DEFAULT 'Pixel 6',
        android_version TEXT DEFAULT '13',
        cpu_cores INTEGER DEFAULT 4,
        ram_mb INTEGER DEFAULT 8192,
        storage_gb INTEGER DEFAULT 128,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        status TEXT DEFAULT 'creating',
        streaming_url TEXT,
        webrtc_offer TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (device_id) REFERENCES devices(id)
    );

    CREATE TABLE IF NOT EXISTS tokens (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        expires_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    `

    _, err = db.Exec(createTables)
    if err != nil {
        log.Fatal("Failed to create tables:", err)
    }

    log.Println("✅ Database initialized successfully")
}

// Handlers
func homeHandler(w http.ResponseWriter, r *http.Request) {
    jsonResponse(w, http.StatusOK, map[string]string{
        "message": "MobileVault Backend API",
        "status":  "running",
        "version": "1.0.0",
    })
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
    jsonResponse(w, http.StatusOK, map[string]interface{}{
        "status":    "healthy",
        "timestamp": time.Now().Format(time.RFC3339),
        "database":  "sqlite",
    })
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        jsonError(w, http.StatusBadRequest, "Invalid request body")
        return
    }

    // Check if user exists
    var existingID string
    err := db.QueryRow("SELECT id FROM users WHERE email = ?", req.Email).Scan(&existingID)
    if err == nil {
        jsonError(w, http.StatusConflict, "User already exists")
        return
    }

    // Create user
    userID := uuid.New().String()
    passwordHash := hashPassword(req.Password)

    _, err = db.Exec(
        "INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)",
        userID, req.Email, passwordHash,
    )
    if err != nil {
        jsonError(w, http.StatusInternalServerError, "Failed to create user")
        return
    }

    // Create default device
    deviceID := uuid.New().String()
    _, err = db.Exec(`
        INSERT INTO devices 
        (id, user_id, name, model, android_version, cpu_cores, ram_mb, storage_gb)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        deviceID, userID, "My Cloud Phone", "Pixel 6", "13", 4, 8192, 128,
    )
    if err != nil {
        log.Printf("Warning: Failed to create default device: %v", err)
    }

    // Generate JWT token
    token, err := generateToken(userID, req.Email)
    if err != nil {
        jsonError(w, http.StatusInternalServerError, "Failed to generate token")
        return
    }

    jsonResponse(w, http.StatusCreated, map[string]interface{}{
        "user": map[string]interface{}{
            "id":    userID,
            "email": req.Email,
            "tier":  "free",
        },
        "token": token,
    })
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        jsonError(w, http.StatusBadRequest, "Invalid request body")
        return
    }

    // Get user
    var userID, email, passwordHash, tier string
    err := db.QueryRow(
        "SELECT id, email, password_hash, tier FROM users WHERE email = ?",
        req.Email,
    ).Scan(&userID, &email, &passwordHash, &tier)

    if err != nil || !verifyPassword(req.Password, passwordHash) {
        jsonError(w, http.StatusUnauthorized, "Invalid credentials")
        return
    }

    // Generate token
    token, err := generateToken(userID, email)
    if err != nil {
        jsonError(w, http.StatusInternalServerError, "Failed to generate token")
        return
    }

    jsonResponse(w, http.StatusOK, map[string]interface{}{
        "user": map[string]interface{}{
            "id":    userID,
            "email": email,
            "tier":  tier,
        },
        "token": token,
    })
}

func getDevicesHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)

    rows, err := db.Query(`
        SELECT id, name, model, android_version, cpu_cores, ram_mb, storage_gb, created_at
        FROM devices WHERE user_id = ? ORDER BY created_at DESC`,
        userID,
    )
    if err != nil {
        jsonError(w, http.StatusInternalServerError, "Failed to fetch devices")
        return
    }
    defer rows.Close()

    devices := []map[string]interface{}{}
    for rows.Next() {
        var device struct {
            ID             string    `json:"id"`
            Name           string    `json:"name"`
            Model          string    `json:"model"`
            AndroidVersion string    `json:"android_version"`
            CPUCores       int       `json:"cpu_cores"`
            RAMMB          int       `json:"ram_mb"`
            StorageGB      int       `json:"storage_gb"`
            CreatedAt      time.Time `json:"created_at"`
        }

        err := rows.Scan(
            &device.ID, &device.Name, &device.Model, &device.AndroidVersion,
            &device.CPUCores, &device.RAMMB, &device.StorageGB, &device.CreatedAt,
        )
        if err != nil {
            continue
        }

        devices = append(devices, map[string]interface{}{
            "id":             device.ID,
            "name":           device.Name,
            "model":          device.Model,
            "android_version": device.AndroidVersion,
            "cpu_cores":      device.CPUCores,
            "ram_mb":         device.RAMMB,
            "storage_gb":     device.StorageGB,
            "created_at":     device.CreatedAt.Format(time.RFC3339),
        })
    }

    jsonResponse(w, http.StatusOK, devices)
}

func createDeviceHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)

    var req struct {
        Name           string `json:"name"`
        Model          string `json:"model"`
        AndroidVersion string `json:"android_version"`
        CPUCores       int    `json:"cpu_cores"`
        RAMMB          int    `json:"ram_mb"`
        StorageGB      int    `json:"storage_gb"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        jsonError(w, http.StatusBadRequest, "Invalid request body")
        return
    }

    // Set defaults
    if req.Model == "" {
        req.Model = "Pixel 6"
    }
    if req.AndroidVersion == "" {
        req.AndroidVersion = "13"
    }
    if req.CPUCores == 0 {
        req.CPUCores = 4
    }
    if req.RAMMB == 0 {
        req.RAMMB = 8192
    }
    if req.StorageGB == 0 {
        req.StorageGB = 128
    }

    deviceID := uuid.New().String()
    createdAt := time.Now()

    _, err := db.Exec(`
        INSERT INTO devices 
        (id, user_id, name, model, android_version, cpu_cores, ram_mb, storage_gb, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        deviceID, userID, req.Name, req.Model, req.AndroidVersion,
        req.CPUCores, req.RAMMB, req.StorageGB, createdAt,
    )
    if err != nil {
        jsonError(w, http.StatusInternalServerError, "Failed to create device")
        return
    }

    jsonResponse(w, http.StatusCreated, map[string]interface{}{
        "id":             deviceID,
        "user_id":        userID,
        "name":           req.Name,
        "model":          req.Model,
        "android_version": req.AndroidVersion,
        "cpu_cores":      req.CPUCores,
        "ram_mb":         req.RAMMB,
        "storage_gb":     req.StorageGB,
        "created_at":     createdAt.Format(time.RFC3339),
    })
}

func createSessionHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)

    var req struct {
        DeviceID string `json:"device_id"`
        Region   string `json:"region"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        jsonError(w, http.StatusBadRequest, "Invalid request body")
        return
    }

    // Verify device belongs to user
    var deviceExists bool
    err := db.QueryRow(
        "SELECT EXISTS(SELECT 1 FROM devices WHERE id = ? AND user_id = ?)",
        req.DeviceID, userID,
    ).Scan(&deviceExists)
    
    if err != nil || !deviceExists {
        jsonError(w, http.StatusNotFound, "Device not found")
        return
    }

    // Create session
    sessionID := uuid.New().String()
    createdAt := time.Now()
    
    // Generate WebRTC offer (simulated)
    webrtcOffer := `{"type":"offer","sdp":"v=0\r\no=- 123456 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\na=msid-semantic: WMS\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\nc=IN IP4 0.0.0.0\r\na=rtcp:9 IN IP4 0.0.0.0\r\na=ice-ufrag:xxx\r\na=ice-pwd:xxx\r\na=fingerprint:sha-256 xxx\r\na=setup:actpass\r\na=mid:0\r\na=sendrecv\r\na=rtcp-mux\r\na=rtcp-rsize\r\na=rtpmap:96 VP8/90000\r\na=rtcp-fb:96 goog-remb\r\na=rtcp-fb:96 transport-cc\r\na=rtcp-fb:96 ccm fir\r\na=rtcp-fb:96 nack\r\na=rtcp-fb:96 nack pli\r\n"}`
    
    streamingURL := fmt.Sprintf("wss://stream.mobilevault.com/session/%s", sessionID)

    _, err = db.Exec(`
        INSERT INTO sessions 
        (id, user_id, device_id, status, streaming_url, webrtc_offer, created_at, last_activity)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        sessionID, userID, req.DeviceID, "active", streamingURL, webrtcOffer, createdAt, createdAt,
    )
    if err != nil {
        jsonError(w, http.StatusInternalServerError, "Failed to create session")
        return
    }

    jsonResponse(w, http.StatusCreated, map[string]interface{}{
        "id":           sessionID,
        "user_id":      userID,
        "device_id":    req.DeviceID,
        "status":       "active",
        "streaming_url": streamingURL,
        "webrtc_offer": webrtcOffer,
        "created_at":   createdAt.Format(time.RFC3339),
    })
}

func getSessionHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)
    vars := mux.Vars(r)
    sessionID := vars["id"]

    var session struct {
        ID           string
        UserID       string
        DeviceID     string
        Status       string
        StreamingURL string
        WebRTCOffer  string
        CreatedAt    time.Time
        LastActivity time.Time
    }

    err := db.QueryRow(`
        SELECT id, user_id, device_id, status, streaming_url, webrtc_offer, created_at, last_activity
        FROM sessions WHERE id = ? AND user_id = ?`,
        sessionID, userID,
    ).Scan(
        &session.ID, &session.UserID, &session.DeviceID, &session.Status,
        &session.StreamingURL, &session.WebRTCOffer, &session.CreatedAt, &session.LastActivity,
    )

    if err != nil {
        jsonError(w, http.StatusNotFound, "Session not found")
        return
    }

    jsonResponse(w, http.StatusOK, map[string]interface{}{
        "id":            session.ID,
        "user_id":       session.UserID,
        "device_id":     session.DeviceID,
        "status":        session.Status,
        "streaming_url": session.StreamingURL,
        "webrtc_offer":  session.WebRTCOffer,
        "created_at":    session.CreatedAt.Format(time.RFC3339),
        "last_activity": session.LastActivity.Format(time.RFC3339),
    })
}

func terminateSessionHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)
    vars := mux.Vars(r)
    sessionID := vars["id"]

    // Verify session belongs to user
    var sessionExists bool
    err := db.QueryRow(
        "SELECT EXISTS(SELECT 1 FROM sessions WHERE id = ? AND user_id = ?)",
        sessionID, userID,
    ).Scan(&sessionExists)
    
    if err != nil || !sessionExists {
        jsonError(w, http.StatusNotFound, "Session not found")
        return
    }

    // Update session status
    _, err = db.Exec(
        "UPDATE sessions SET status = 'terminated', last_activity = ? WHERE id = ?",
        time.Now(), sessionID,
    )
    if err != nil {
        jsonError(w, http.StatusInternalServerError, "Failed to terminate session")
        return
    }

    jsonResponse(w, http.StatusOK, map[string]string{
        "status":  "terminated",
        "message": "Session terminated successfully",
    })
}

// Auth middleware
func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            jsonError(w, http.StatusUnauthorized, "Authorization header required")
            return
        }

        // Expect "Bearer <token>"
        if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
            jsonError(w, http.StatusUnauthorized, "Invalid authorization header")
            return
        }

        tokenString := authHeader[7:]
        
        // Parse JWT token
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
            }
            return jwtSecret, nil
        })

        if err != nil || !token.Valid {
            jsonError(w, http.StatusUnauthorized, "Invalid token")
            return
        }

        // Extract claims
        claims, ok := token.Claims.(jwt.MapClaims)
        if !ok {
            jsonError(w, http.StatusUnauthorized, "Invalid token claims")
            return
        }

        userID, ok := claims["user_id"].(string)
        if !ok {
            jsonError(w, http.StatusUnauthorized, "Invalid user ID in token")
            return
        }

        // Add user ID to context
        ctx := r.Context()
        ctx = context.WithValue(ctx, "user_id", userID)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// Helper functions
func generateToken(userID, email string) (string, error) {
    claims := jwt.MapClaims{
        "user_id": userID,
        "email":   email,
        "exp":     time.Now().Add(24 * time.Hour).Unix(),
        "iat":     time.Now().Unix(),
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(jwtSecret)
}

func hashPassword(password string) string {
    // In production, use bcrypt or argon2
    // For development, we'll use a simple hash
    import "crypto/sha256"
    hash := sha256.Sum256([]byte(password))
    return fmt.Sprintf("%x", hash)
}

func verifyPassword(password, hashed string) bool {
    return hashPassword(password) == hashed
}

func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, status int, message string) {
    jsonResponse(w, status, map[string]string{"error": message})
}