package orchestrator

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Tony-Bridges/mobilevault-backendv1/db"
	"github.com/Tony-Bridges/mobilevault-backendv1/models"
	"github.com/google/uuid"
)

type OrchestratorService struct {
	db        *db.Repository
	scheduler *SchedulerService
	snapshot  *SnapshotService
}

func NewOrchestratorService(dbRepo *db.Repository) *OrchestratorService {
	return &OrchestratorService{
		db:        dbRepo,
		scheduler: NewSchedulerService(dbRepo),
		snapshot:  NewSnapshotService(dbRepo),
	}
}

func (s *OrchestratorService) CreateSession(ctx context.Context, req *models.CreateSessionRequest, userID string) (*models.CreateSessionResponse, error) {
	// 1. Get or create default snapshot
	snapshotID := req.SnapshotID
	if snapshotID == "" {
		// Create default snapshot for device
		snapshot, err := s.snapshot.CreateDefaultSnapshot(ctx, userID, req.DeviceID)
		if err != nil {
			return nil, fmt.Errorf("failed to create default snapshot: %w", err)
		}
		snapshotID = snapshot.ID
	}

	// 2. Check for existing active session
	existingSession, err := s.db.GetActiveSession(ctx, userID, req.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing session: %w", err)
	}
	if existingSession != nil {
		return &models.CreateSessionResponse{
			SessionID:    existingSession.ID,
			StreamingURL: existingSession.StreamingURL,
			WebRTCOffer:  existingSession.WebRTCOffer,
			Status:       existingSession.Status,
		}, nil
	}

	// 3. Schedule VM on available host
	region := req.Region
	if region == "" {
		// Get user's default region from settings
		region = "us-east-1" // Default for now
	}

	vmHost, err := s.scheduler.ScheduleVM(ctx, region, false) // requireGPU false for now
	if err != nil {
		return nil, fmt.Errorf("failed to schedule VM: %w", err)
	}

	// 4. Create session overlay
	overlayPath, err := s.snapshot.CreateSessionOverlay(ctx, snapshotID)
	if err != nil {
		return nil, fmt.Errorf("failed to create session overlay: %w", err)
	}

	// 5. Create VM session record
	sessionID := uuid.New().String()
	session := &models.VMSession{
		ID:           sessionID,
		UserID:       userID,
		DeviceID:     req.DeviceID,
		SnapshotID:   snapshotID,
		VMHostID:     vmHost.ID,
		OverlayPath:  overlayPath,
		Status:       "creating",
		CreatedAt:    time.Now(),
		StartedAt:    time.Now(),
		LastActivity: time.Now(),
	}

	if err := s.db.CreateVMSession(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to create session record: %w", err)
	}

	// 6. Trigger VM provisioning (async)
	go s.provisionVM(session, vmHost)

	return &models.CreateSessionResponse{
		SessionID: sessionID,
		Status:    "creating",
	}, nil
}

func (s *OrchestratorService) provisionVM(session *models.VMSession, vmHost *models.VMHost) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// This would communicate with the VM host agent
	// For MVP, we'll simulate this

	log.Printf("Provisioning VM on host %s for session %s", vmHost.Hostname, session.ID)

	// Simulate VM provisioning time
	time.Sleep(5 * time.Second)

	// Generate WebRTC offer (simulated)
	webrtcOffer := `{"type":"offer","sdp":"v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\na=msid-semantic: WMS\r\nm=video 9 UDP/TLS/RTP/SAVPF 96 97 98 99 100 101 102 121 127 120 125 107 108 109 124 119 123 118 114 115 116\r\nc=IN IP4 0.0.0.0\r\na=rtcp:9 IN IP4 0.0.0.0\r\na=ice-ufrag:xxx\r\na=ice-pwd:xxx\r\na=ice-options:trickle\r\na=fingerprint:sha-256 xxx\r\na=setup:actpass\r\na=mid:0\r\na=extmap:1 urn:ietf:params:rtp-hdrext:toffset\r\na=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\na=extmap:3 urn:3gpp:video-orientation\r\na=sendrecv\r\na=rtcp-mux\r\na=rtcp-rsize\r\na=rtpmap:96 VP8/90000\r\na=rtcp-fb:96 goog-remb\r\na=rtcp-fb:96 transport-cc\r\na=rtcp-fb:96 ccm fir\r\na=rtcp-fb:96 nack\r\na=rtcp-fb:96 nack pli\r\na=rtpmap:97 rtx/90000\r\na=fmtp:97 apt=96\r\na=rtpmap:98 VP9/90000\r\na=rtcp-fb:98 goog-remb\r\na=rtcp-fb:98 transport-cc\r\na=rtcp-fb:98 ccm fir\r\na=rtcp-fb:98 nack\r\na=rtcp-fb:98 nack pli\r\na=fmtp:98 profile-id=0\r\na=rtpmap:99 rtx/90000\r\na=fmtp:99 apt=98\r\na=rtpmap:100 H264/90000\r\na=rtcp-fb:100 goog-remb\r\na=rtcp-fb:100 transport-cc\r\na=rtcp-fb:100 ccm fir\r\na=rtcp-fb:100 nack\r\na=rtcp-fb:100 nack pli\r\na=fmtp:100 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f\r\na=rtpmap:101 rtx/90000\r\na=fmtp:101 apt=100\r\na=rtpmap:102 H264/90000\r\na=rtcp-fb:102 goog-remb\r\na=rtcp-fb:102 transport-cc\r\na=rtcp-fb:102 ccm fir\r\na=rtcp-fb:102 nack\r\na=rtcp-fb:102 nack pli\r\na=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\na=rtpmap:121 rtx/90000\r\na=fmtp:121 apt=102\r\na=rtpmap:127 H264/90000\r\na=rtcp-fb:127 goog-remb\r\na=rtcp-fb:127 transport-cc\r\na=rtcp-fb:127 ccm fir\r\na=rtcp-fb:127 nack\r\na=rtcp-fb:127 nack pli\r\na=fmtp:127 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f\r\na=rtpmap:120 rtx/90000\r\na=fmtp:120 apt=127\r\na=rtpmap:125 H264/90000\r\na=rtcp-fb:125 goog-remb\r\na=rtcp-fb:125 transport-cc\r\na=rtcp-fb:125 ccm fir\r\na=rtcp-fb:125 nack\r\na=rtcp-fb:125 nack pli\r\na=fmtp:125 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=4d001f\r\na=rtpmap:107 rtx/90000\r\na=fmtp:107 apt=125\r\na=rtpmap:108 H264/90000\r\na=rtcp-fb:108 goog-remb\r\na=rtcp-fb:108 transport-cc\r\na=rtcp-fb:108 ccm fir\r\na=rtcp-fb:108 nack\r\na=rtcp-fb:108 nack pli\r\na=fmtp:108 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=4d001f\r\na=rtpmap:109 rtx/90000\r\na=fmtp:109 apt=108\r\na=rtpmap:124 H264/90000\r\na=rtcp-fb:124 goog-remb\r\na=rtcp-fb:124 transport-cc\r\na=rtcp-fb:124 ccm fir\r\na=rtcp-fb:124 nack\r\na=rtcp-fb:124 nack pli\r\na=fmtp:124 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=64001f\r\na=rtpmap:119 rtx/90000\r\na=fmtp:119 apt=124\r\na=rtpmap:123 red/90000\r\na=rtpmap:118 rtx/90000\r\na=fmtp:118 apt=123\r\na=rtpmap:114 ulpfec/90000\r\na=rtpmap:115 flexfec-03/90000\r\na=rtcp-fb:115 goog-remb\r\na=rtcp-fb:115 transport-cc\r\na=rtpmap:116 flexfec-03/90000\r\na=rtcp-fb:116 goog-remb\r\na=rtcp-fb:116 transport-cc\r\n"}`

	// Update session with streaming URL and WebRTC offer
	streamingURL := fmt.Sprintf("wss://%s/stream/%s", vmHost.IPAddress, session.ID)

	// In real implementation, you'd call the VM host API
	// For now, we'll update the database
	if err := s.db.UpdateVMSessionStatus(ctx, session.ID, "active"); err != nil {
		log.Printf("Failed to update session status: %v", err)
		return
	}

	// Store WebRTC offer in Redis for later retrieval
	// (Implementation depends on your Redis setup)
	log.Printf("VM provisioned for session %s. Streaming URL: %s", session.ID, streamingURL)
}

func (s *OrchestratorService) TerminateSession(ctx context.Context, sessionID, userID string) error {
	// Update session status to terminating
	if err := s.db.UpdateVMSessionStatus(ctx, sessionID, "terminating"); err != nil {
		return err
	}

	// TODO: Signal VM host to terminate the VM
	// This would involve calling the VM host agent API

	// Update session status to terminated
	if err := s.db.UpdateVMSessionStatus(ctx, sessionID, "terminated"); err != nil {
		return err
	}

	return nil
}
