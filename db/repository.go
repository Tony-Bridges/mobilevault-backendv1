package db

import (
	"context"
	"fmt"

	"github.com/Tony-Bridges/mobilevault-backendv1/models"
	"github.com/jackc/pgx/v5"
)

type Repository struct {
	db *Database
}

func NewRepository(db *Database) *Repository {
	return &Repository{db: db}
}

// User methods
func (r *Repository) CreateUser(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (id, email, encrypted_master_key, created_at, subscription_tier, metadata)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := r.db.Postgres.Exec(ctx, query,
		user.ID, user.Email, user.EncryptedMasterKey,
		user.CreatedAt, user.SubscriptionTier, user.Metadata,
	)
	return err
}

func (r *Repository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `SELECT * FROM users WHERE email = $1 AND is_active = true`
	row := r.db.Postgres.QueryRow(ctx, query, email)

	var user models.User
	err := row.Scan(
		&user.ID, &user.Email, &user.EncryptedMasterKey,
		&user.CreatedAt, &user.LastLogin, &user.IsActive,
		&user.SubscriptionTier, &user.Metadata,
	)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// Device methods
func (r *Repository) CreateDevice(ctx context.Context, device *models.Device) error {
	query := `
		INSERT INTO devices (
			id, user_id, name, model, android_version, cpu_cores,
			ram_mb, storage_gb, gpu_enabled, is_active, created_at, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`
	_, err := r.db.Postgres.Exec(ctx, query,
		device.ID, device.UserID, device.Name, device.Model,
		device.AndroidVersion, device.CPUCores, device.RAMMB,
		device.StorageGB, device.GPUEnabled, device.IsActive,
		device.CreatedAt, device.Metadata,
	)
	return err
}

func (r *Repository) GetUserDevices(ctx context.Context, userID string) ([]models.Device, error) {
	query := `
		SELECT * FROM devices 
		WHERE user_id = $1 AND is_active = true
		ORDER BY last_used_at DESC NULLS LAST
	`
	rows, err := r.db.Postgres.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []models.Device
	for rows.Next() {
		var device models.Device
		err := rows.Scan(
			&device.ID, &device.UserID, &device.Name, &device.Model,
			&device.AndroidVersion, &device.CPUCores, &device.RAMMB,
			&device.StorageGB, &device.GPUEnabled, &device.IsActive,
			&device.CreatedAt, &device.LastUsedAt, &device.Metadata,
		)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	return devices, nil
}

// Snapshot methods
func (r *Repository) CreateSnapshot(ctx context.Context, snapshot *models.Snapshot) error {
	query := `
		INSERT INTO snapshots (
			id, user_id, device_id, parent_snapshot_id, name,
			storage_path, size_bytes, is_base, is_auto, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err := r.db.Postgres.Exec(ctx, query,
		snapshot.ID, snapshot.UserID, snapshot.DeviceID,
		snapshot.ParentSnapshotID, snapshot.Name, snapshot.StoragePath,
		snapshot.SizeBytes, snapshot.IsBase, snapshot.IsAuto,
		snapshot.Metadata, snapshot.CreatedAt,
	)
	return err
}

func (r *Repository) GetUserSnapshots(ctx context.Context, userID string) ([]models.Snapshot, error) {
	query := `
		SELECT * FROM snapshots 
		WHERE user_id = $1
		ORDER BY created_at DESC
	`
	rows, err := r.db.Postgres.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var snapshots []models.Snapshot
	for rows.Next() {
		var snapshot models.Snapshot
		err := rows.Scan(
			&snapshot.ID, &snapshot.UserID, &snapshot.DeviceID,
			&snapshot.ParentSnapshotID, &snapshot.Name, &snapshot.StoragePath,
			&snapshot.SizeBytes, &snapshot.IsBase, &snapshot.IsAuto,
			&snapshot.Metadata, &snapshot.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

// VM Session methods
func (r *Repository) CreateVMSession(ctx context.Context, session *models.VMSession) error {
	query := `
		INSERT INTO vm_sessions (
			id, user_id, device_id, snapshot_id, vm_host_id,
			overlay_path, streaming_url, webrtc_offer, status,
			created_at, started_at, last_activity
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`
	_, err := r.db.Postgres.Exec(ctx, query,
		session.ID, session.UserID, session.DeviceID, session.SnapshotID,
		session.VMHostID, session.OverlayPath, session.StreamingURL,
		session.WebRTCOffer, session.Status, session.CreatedAt,
		session.StartedAt, session.LastActivity,
	)
	return err
}

func (r *Repository) GetActiveSession(ctx context.Context, userID, deviceID string) (*models.VMSession, error) {
	query := `
		SELECT * FROM vm_sessions 
		WHERE user_id = $1 AND device_id = $2 AND status IN ('active', 'creating')
		ORDER BY created_at DESC
		LIMIT 1
	`
	row := r.db.Postgres.QueryRow(ctx, query, userID, deviceID)

	var session models.VMSession
	err := row.Scan(
		&session.ID, &session.UserID, &session.DeviceID, &session.SnapshotID,
		&session.VMHostID, &session.OverlayPath, &session.StreamingURL,
		&session.WebRTCOffer, &session.Status, &session.CreatedAt,
		&session.StartedAt, &session.EndedAt, &session.LastActivity,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// VM Host methods
func (r *Repository) FindAvailableVMHost(ctx context.Context, region string, requireGPU bool) (*models.VMHost, error) {
	query := `
		SELECT * FROM vm_hosts 
		WHERE region = $1 
		AND is_active = true 
		AND current_sessions < max_sessions
		AND last_heartbeat > NOW() - INTERVAL '1 minute'
		AND ($2 = false OR capacity_gpu = true)
		ORDER BY current_sessions ASC, available_cpu DESC
		LIMIT 1
	`
	row := r.db.Postgres.QueryRow(ctx, query, region, requireGPU)

	var host models.VMHost
	err := row.Scan(
		&host.ID, &host.Hostname, &host.Region, &host.IPAddress,
		&host.CapacityCPU, &host.CapacityRAMMB, &host.CapacityGPU,
		&host.AvailableCPU, &host.AvailableRAMMB, &host.CurrentSessions,
		&host.MaxSessions, &host.IsActive, &host.LastHeartbeat,
		&host.Metadata,
	)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("no available VM host in region %s", region)
	}
	if err != nil {
		return nil, err
	}
	return &host, nil
}

func (r *Repository) UpdateVMSessionStatus(ctx context.Context, sessionID, status string) error {
	query := `UPDATE vm_sessions SET status = $1, last_activity = NOW() WHERE id = $2`
	_, err := r.db.Postgres.Exec(ctx, query, status, sessionID)
	return err
}
