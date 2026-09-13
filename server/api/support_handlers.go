package api

import (
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/internal/privatefile"
)

const (
	supportLogSchemaVersion1     = 1
	supportLogSchemaVersion2     = 2
	maxSupportLogCompressedBytes = 8 << 20
	maxSupportLogExpandedBytes   = 32 << 20
	maxSupportLogFilesV1         = 3
	maxSupportLogRoomInstances   = 8
	maxSupportLogInstancesV2     = 1 + maxSupportLogRoomInstances
	maxSupportLogFilesV2         = 2 + (maxSupportLogRoomInstances * 2)
	maxSupportLogOmittedRooms    = maxSupportLogRoomInstances * 2
	defaultSupportLogRetention   = 14 * 24 * time.Hour
)

type supportLogBundle struct {
	SchemaVersion int                    `json:"schema_version"`
	UploadedAt    string                 `json:"uploaded_at"`
	DeviceName    string                 `json:"device_name"`
	Platform      string                 `json:"platform"`
	ClientBuild   map[string]string      `json:"client_build,omitempty"`
	DaemonBuild   map[string]string      `json:"daemon_build,omitempty"`
	Files         []supportLogBundleFile `json:"files,omitempty"`
	Manifest      *supportLogManifest    `json:"manifest,omitempty"`
	Instances     []supportLogInstance   `json:"instances,omitempty"`
}

type supportLogManifest struct {
	TotalInstances        int      `json:"total_instances"`
	NetworkIDs            []string `json:"network_ids,omitempty"`
	HasRoomLogs           bool     `json:"has_room_logs"`
	RetainedRoomInstances int      `json:"retained_room_instances,omitempty"`
	OmittedRoomInstances  int      `json:"omitted_room_instances,omitempty"`
	OmittedReason         string   `json:"omitted_reason,omitempty"`
}

type supportLogInstance struct {
	InstanceType  string            `json:"instance_type"` // "main" or "room"
	NetworkID     string            `json:"network_id,omitempty"`
	ProfileID     string            `json:"profile_id,omitempty"`
	BootID        string            `json:"boot_id,omitempty"`
	Build         map[string]string `json:"build,omitempty"`
	StartedAt     string            `json:"started_at,omitempty"`
	EndedAt       string            `json:"ended_at,omitempty"`
	Truncated     bool              `json:"truncated"`
	StatusSummary string            `json:"status_summary,omitempty"`
	Log           string            `json:"log,omitempty"`
}

type supportLogBundleFile struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

type storedSupportLogBundle struct {
	UploadID   string           `json:"upload_id"`
	ReceivedAt string           `json:"received_at"`
	UserID     string           `json:"user_id"`
	Bundle     supportLogBundle `json:"bundle"`
}

// UploadSupportLogs handles POST /api/v1/support/logs.
//
// The client sends a gzip-compressed JSON bundle rather than a multipart
// archive. This keeps the format inspectable over SSH while allowing the
// server to enforce both compressed and expanded size limits. Only the
// current client/daemon startup files are accepted by the client; the server
// never accepts a client-controlled destination path.
func (s *Server) UploadSupportLogs(w http.ResponseWriter, r *http.Request) {
	claims, err := auth.GetClaims(r.Context())
	if err != nil {
		http.Error(w, `{"error":"user authentication required"}`, http.StatusUnauthorized)
		return
	}

	if r.ContentLength > maxSupportLogCompressedBytes {
		http.Error(w, `{"error":"support log bundle is too large"}`, http.StatusRequestEntityTooLarge)
		return
	}

	if encoding := strings.TrimSpace(strings.ToLower(r.Header.Get("Content-Encoding"))); encoding != "gzip" {
		http.Error(w, `{"error":"support log bundle must use gzip encoding"}`, http.StatusUnsupportedMediaType)
		return
	}

	gzipReader, err := gzip.NewReader(io.LimitReader(r.Body, maxSupportLogCompressedBytes+1))
	if err != nil {
		http.Error(w, `{"error":"invalid gzip support log bundle"}`, http.StatusBadRequest)
		return
	}
	decompressed, readErr := io.ReadAll(io.LimitReader(gzipReader, maxSupportLogExpandedBytes+1))
	closeErr := gzipReader.Close()
	if readErr != nil || closeErr != nil {
		http.Error(w, `{"error":"invalid support log bundle"}`, http.StatusBadRequest)
		return
	}
	if len(decompressed) > maxSupportLogExpandedBytes {
		http.Error(w, `{"error":"expanded support log bundle is too large"}`, http.StatusRequestEntityTooLarge)
		return
	}

	var bundle supportLogBundle
	if err := json.Unmarshal(decompressed, &bundle); err != nil {
		http.Error(w, `{"error":"invalid support log JSON"}`, http.StatusBadRequest)
		return
	}
	instanceCount, err := validateSupportLogBundle(bundle)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	uploadID, err := newSupportLogUploadID()
	if err != nil {
		http.Error(w, `{"error":"could not allocate support log id"}`, http.StatusInternalServerError)
		return
	}
	receivedAt := time.Now().UTC()
	stored := storedSupportLogBundle{
		UploadID:   uploadID,
		ReceivedAt: receivedAt.Format(time.RFC3339Nano),
		UserID:     claims.UserID,
		Bundle:     bundle,
	}

	if err := persistSupportLogBundle(s.supportLogDir, uploadID, stored); err != nil {
		http.Error(w, `{"error":"support log storage failed"}`, http.StatusInternalServerError)
		return
	}
	pruneSupportLogBundles(s.supportLogDir, receivedAt)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":     true,
		"upload_id":   uploadID,
		"received_at": receivedAt.Format(time.RFC3339Nano),
		"instances":   instanceCount,
	})
}

func supportLogDirFromEnv() string {
	if value := strings.TrimSpace(os.Getenv("LOG_UPLOAD_DIR")); value != "" {
		return value
	}
	return filepath.Join("data", "log-uploads")
}

func isAllowedSupportLogFileName(name string, schemaVersion int) bool {
	if name == "p2wlan-daemon.log" || name == "p2wlan-client.log" {
		return true
	}
	if schemaVersion < supportLogSchemaVersion2 {
		return false
	}
	if name == "p2wlan-room.log" || name == "status-summary.json" {
		return true
	}
	parts := strings.Split(name, "/")
	if len(parts) == 3 && parts[0] == "rooms" {
		if isValidHex64(parts[1]) {
			fileName := parts[2]
			return fileName == "p2wlan-daemon.log" || fileName == "p2wlan-room.log" || fileName == "status-summary.json"
		}
	}
	return false
}

func isValidHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < 64; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func validateSupportLogBundle(bundle supportLogBundle) (int, error) {
	if bundle.SchemaVersion != supportLogSchemaVersion1 && bundle.SchemaVersion != supportLogSchemaVersion2 {
		return 0, fmt.Errorf("unsupported support log schema version")
	}
	if len(bundle.DeviceName) > 128 || len(bundle.Platform) > 64 {
		return 0, fmt.Errorf("support log metadata is too long")
	}
	maxFiles := maxSupportLogFilesV1
	if bundle.SchemaVersion >= supportLogSchemaVersion2 {
		maxFiles = maxSupportLogFilesV2
	}
	if len(bundle.Files) == 0 && len(bundle.Instances) == 0 {
		return 0, fmt.Errorf("support log bundle is empty")
	}
	if len(bundle.Files) > maxFiles {
		return 0, fmt.Errorf("support log bundle contains too many files")
	}
	maxInstances := maxSupportLogFilesV1
	if bundle.SchemaVersion >= supportLogSchemaVersion2 {
		maxInstances = maxSupportLogInstancesV2
	}
	if len(bundle.Instances) > maxInstances {
		return 0, fmt.Errorf("support log bundle contains too many instances")
	}
	seen := make(map[string]struct{}, len(bundle.Files))
	roomProfiles := make(map[string]struct{})
	roomLogFiles := make(map[string]struct{})
	hasLegacyRoomFiles := false
	for _, file := range bundle.Files {
		if !isAllowedSupportLogFileName(file.Name, bundle.SchemaVersion) {
			return 0, fmt.Errorf("unsupported support log file: %s", file.Name)
		}
		if _, ok := seen[file.Name]; ok {
			return 0, fmt.Errorf("duplicate support log file: %s", file.Name)
		}
		seen[file.Name] = struct{}{}
		if len(file.Content) == 0 {
			return 0, fmt.Errorf("support log file is empty: %s", file.Name)
		}
		if len(file.Content) > maxSupportLogExpandedBytes {
			return 0, fmt.Errorf("support log file is too large: %s", file.Name)
		}
		if profileID, fileName, ok := supportLogRoomFileName(file.Name); ok {
			roomProfiles[profileID] = struct{}{}
			if fileName != "status-summary.json" {
				if _, exists := roomLogFiles[profileID]; exists {
					return 0, fmt.Errorf("multiple room log files for profile_id: %s", profileID)
				}
				roomLogFiles[profileID] = struct{}{}
			}
		} else if file.Name == "p2wlan-room.log" || file.Name == "status-summary.json" {
			hasLegacyRoomFiles = true
		}
	}
	if len(roomProfiles) > maxSupportLogRoomInstances {
		return 0, fmt.Errorf("support log bundle contains too many room instances")
	}
	if hasLegacyRoomFiles && len(roomProfiles) >= maxSupportLogRoomInstances {
		return 0, fmt.Errorf("support log bundle contains too many room instances")
	}

	instanceCount := 1 + len(roomProfiles)
	if hasLegacyRoomFiles {
		instanceCount++
	}
	if len(bundle.Files) == 0 {
		instanceCount = len(bundle.Instances)
	}
	instanceProfiles := make(map[string]struct{})
	for _, inst := range bundle.Instances {
		if inst.InstanceType != "main" && inst.InstanceType != "room" {
			return 0, fmt.Errorf("invalid instance_type: %s", inst.InstanceType)
		}
		if inst.ProfileID != "" && !isValidHex64(inst.ProfileID) {
			return 0, fmt.Errorf("invalid profile_id: %s", inst.ProfileID)
		}
		if inst.InstanceType == "room" && inst.ProfileID != "" {
			if _, ok := instanceProfiles[inst.ProfileID]; ok {
				return 0, fmt.Errorf("duplicate room instance profile_id: %s", inst.ProfileID)
			}
			instanceProfiles[inst.ProfileID] = struct{}{}
		}
		if len(inst.Log) > maxSupportLogExpandedBytes {
			return 0, fmt.Errorf("instance log is too large")
		}
		if len(inst.StatusSummary) > maxSupportLogExpandedBytes {
			return 0, fmt.Errorf("instance status summary is too large")
		}
	}
	if len(bundle.Files) > 0 && len(bundle.Instances) > 0 && len(bundle.Instances) != instanceCount {
		return 0, fmt.Errorf("support log instances do not match file instance count")
	}
	if bundle.Manifest != nil {
		if bundle.Manifest.TotalInstances <= 0 || bundle.Manifest.TotalInstances > maxInstances {
			return 0, fmt.Errorf("invalid manifest total_instances")
		}
		if bundle.Manifest.TotalInstances != instanceCount {
			return 0, fmt.Errorf("manifest total_instances (%d) does not match instance count (%d)", bundle.Manifest.TotalInstances, instanceCount)
		}
		// A v2 client may send structured `instances` without duplicating every
		// log in the legacy `files` array. In that form the room count comes from
		// instance_type, not from room file names. Mixed file+instance payloads
		// retain the file-based count for backward compatibility.
		retainedRoomInstances := len(roomProfiles)
		if len(bundle.Files) == 0 {
			retainedRoomInstances = 0
			for _, instance := range bundle.Instances {
				if instance.InstanceType == "room" {
					retainedRoomInstances++
				}
			}
		}
		if hasLegacyRoomFiles {
			retainedRoomInstances++
		}
		if bundle.Manifest.RetainedRoomInstances != 0 && bundle.Manifest.RetainedRoomInstances != retainedRoomInstances {
			return 0, fmt.Errorf("manifest retained_room_instances does not match file room count")
		}
		if bundle.Manifest.OmittedRoomInstances < 0 || bundle.Manifest.OmittedRoomInstances > maxSupportLogOmittedRooms {
			return 0, fmt.Errorf("invalid manifest omitted_room_instances")
		}
		if bundle.Manifest.OmittedRoomInstances == 0 && bundle.Manifest.OmittedReason != "" {
			return 0, fmt.Errorf("manifest omitted_reason requires omitted_room_instances")
		}
		if bundle.Manifest.OmittedRoomInstances > 0 && bundle.Manifest.OmittedReason != "room_instance_budget" {
			return 0, fmt.Errorf("invalid manifest omitted_reason")
		}
		hasRoomLogs := retainedRoomInstances > 0
		if bundle.Manifest.HasRoomLogs != hasRoomLogs {
			return 0, fmt.Errorf("manifest has_room_logs does not match instance count")
		}
	}
	return instanceCount, nil
}

func supportLogRoomFileName(name string) (string, string, bool) {
	parts := strings.Split(name, "/")
	if len(parts) != 3 || parts[0] != "rooms" || !isValidHex64(parts[1]) {
		return "", "", false
	}
	return parts[1], parts[2], true
}

func newSupportLogUploadID() (string, error) {
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(random[:]), nil
}

func persistSupportLogBundle(directory, uploadID string, bundle storedSupportLogBundle) error {
	if strings.TrimSpace(directory) == "" {
		return errors.New("support log directory is empty")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	// Tighten an existing directory as well; this directory is intended for
	// private support artifacts, not public downloads.
	_ = os.Chmod(directory, 0o700)

	encoded, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := privatefile.CreateTemp(directory)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	writer := gzip.NewWriter(tmp)
	if _, err := writer.Write(encoded); err != nil {
		_ = writer.Close()
		_ = tmp.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	finalName := filepath.Join(directory, fmt.Sprintf("%s-%s.json.gz", bundle.ReceivedAt[:10], uploadID))
	return os.Rename(tmpName, finalName)
}

func pruneSupportLogBundles(directory string, now time.Time) {
	retention := defaultSupportLogRetention
	if raw := strings.TrimSpace(os.Getenv("LOG_UPLOAD_RETENTION_DAYS")); raw != "" {
		if days, err := strconv.Atoi(raw); err == nil && days > 0 {
			retention = time.Duration(days) * 24 * time.Hour
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}
	cutoff := now.Add(-retention)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json.gz") {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		_ = os.Remove(filepath.Join(directory, entry.Name()))
	}
}
