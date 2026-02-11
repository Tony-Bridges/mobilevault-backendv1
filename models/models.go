package models

import (
	"time"
)

type User struct {
	ID                string    `json:"id" db:"id"`
	Email             string    `json:"email" db:"email"`
	EncryptedMasterKey []byte   `json:"-" db:"encrypted_master_key"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
	LastLogin         time.Time `json:"last_login" db:"last_login"`
	IsActive          bool      `json:"is_active" db:"is_active"`
	SubscriptionTier  string    `json:"subscription_tier" db:"subscription_tier"`
	Metadata          JSONMap   `json:"metadata" db:"metadata"`
}

type Device struct {
	ID             string    `json:"id" db:"id"`
	UserID         string    `json:"user_id" db:"user_id"`
	Name           string    `json:"name" db:"name"`
	Model          string    `json:"model" db:"model"`
	AndroidVersion string    `json:"android_version" db:"android_version"`
	CPUCores       int       `json:"cpu_cores" db:"cpu_cores"`
	RAMMB          int       `json:"ram_mb" db:"ram_mb"`
	StorageGB      int       `json:"storage_gb" db:"storage_gb"`
	GPUEnabled     bool      `json:"gpu_enabled" db:"gpu_enabled"`
	IsActive       bool      `json:"is_active" db:"is_active"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	LastUsedAt     time.Time `json:"last_used_at" db:"last_used_at"`
	Metadata       JSONMap   `json:"metadata" db:"metadata"`
}

type Snapshot struct {
	ID               string    `json:"id" db:"id"`
	UserID           string    `json:"user_id" db:"user_id"`
	DeviceID         string    `json:"device_id" db:"device_id"`
	ParentSnapshotID string    `json:"parent_snapshot_id" db:"parent_snapshot_id"`
	Name             string    `json:"name" db:"name"`
	StoragePath      string    `json:"storage_path" db:"storage_path"`
	SizeBytes        int64     `json:"size_bytes" db:"size_bytes"`
	IsBase           bool      `json:"is_base" db:"is_base"`
	IsAuto           bool      `json:"is_auto" db:"is_auto"`
	Metadata         JSONMap   `json:"metadata" db:"metadata"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
}

type VMSession struct {
	ID           string    `json:"id" db:"id"`
	UserID       string    `json:"user_id" db:"user_id"`
	DeviceID     string    `json:"device_id" db:"device_id"`
	SnapshotID   string    `json:"snapshot_id" db:"snapshot_id"`
	VMHostID     string    `json:"vm_host_id" db:"vm_host_id"`
	OverlayPath  string    `json:"overlay_path" db:"overlay_path"`
	StreamingURL string    `json:"streaming_url" db:"streaming_url"`
	WebRTCOffer  string    `json:"webrtc_offer" db:"webrtc_offer"`
	Status       string    `json:"status" db:"status"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	StartedAt    time.Time `json:"started_at" db:"started_at"`
	EndedAt      time.Time `json:"ended_at" db:"ended_at"`
	LastActivity time.Time `json:"last_activity" db:"last_activity"`
}

type VMHost struct {
	ID              string    `json:"id" db:"id"`
	Hostname        string    `json:"hostname" db:"hostname"`
	Region          string    `json:"region" db:"region"`
	IPAddress       string    `json:"ip_address" db:"ip_address"`
	CapacityCPU     int       `json:"capacity_cpu" db:"capacity_cpu"`
	CapacityRAMMB   int       `json:"capacity_ram_mb" db:"capacity_ram_mb"`
	CapacityGPU     bool      `json:"capacity_gpu" db:"capacity_gpu"`
	AvailableCPU    int       `json:"available_cpu" db:"available_cpu"`
	AvailableRAMMB  int       `json:"available_ram_mb" db:"available_ram_mb"`
	CurrentSessions int       `json:"current_sessions" db:"current_sessions"`
	MaxSessions     int       `json:"max_sessions" db:"max_sessions"`
	IsActive        bool      `json:"is_active" db:"is_active"`
	LastHeartbeat   time.Time `json:"last_heartbeat" db:"last_heartbeat"`
	Metadata        JSONMap   `json:"metadata" db:"metadata"`
}

type UserSettings struct {
	UserID               string    `json:"user_id" db:"user_id"`
	StreamingQuality     string    `json:"streaming_quality" db:"streaming_quality"`
	AutoSnapshot         bool      `json:"auto_snapshot" db:"auto_snapshot"`
	SnapshotIntervalHours int      `json:"snapshot_interval_hours" db:"snapshot_interval_hours"`
	DefaultRegion        string    `json:"default_region" db:"default_region"`
	CreatedAt            time.Time `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time `json:"updated_at" db:"updated_at"`
}

// Request/Response models
type CreateSessionRequest struct {
	DeviceID   string `json:"device_id" validate:"required"`
	SnapshotID string `json:"snapshot_id"`
	Region     string `json:"region"`
}

type CreateSessionResponse struct {
	SessionID   string `json:"session_id"`
	StreamingURL string `json:"streaming_url"`
	WebRTCOffer string `json:"webrtc_offer"`
	Status      string `json:"status"`
}

type CreateSnapshotRequest struct {
	DeviceID  string `json:"device_id" validate:"required"`
	Name      string `json:"name"`
	IsAuto    bool   `json:"is_auto"`
}

type JSONMap map[string]interface{}