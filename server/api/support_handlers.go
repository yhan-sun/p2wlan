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
)

const (
	supportLogSchemaVersion      = 1
	maxSupportLogCompressedBytes = 8 << 20
	maxSupportLogExpandedBytes   = 32 << 20
	maxSupportLogFiles           = 3
	defaultSupportLogRetention   = 14 * 24 * time.Hour
)

type supportLogBundle struct {
	SchemaVersion int                    `json:"schema_version"`
	UploadedAt    string                 `json:"uploaded_at"`
	DeviceName    string                 `json:"device_name"`
	Platform      string                 `json:"platform"`
	ClientBuild   map[string]string      `json:"client_build,omitempty"`
	DaemonBuild   map[string]string      `json:"daemon_build,omitempty"`
	Files         []supportLogBundleFile `json:"files"`
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
	if err := validateSupportLogBundle(bundle); err != nil {
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
	})
}

func supportLogDirFromEnv() string {
	if value := strings.TrimSpace(os.Getenv("LOG_UPLOAD_DIR")); value != "" {
		return value
	}
	return filepath.Join("data", "log-uploads")
}

func validateSupportLogBundle(bundle supportLogBundle) error {
	if bundle.SchemaVersion != supportLogSchemaVersion {
		return fmt.Errorf("unsupported support log schema version")
	}
	if len(bundle.DeviceName) > 128 || len(bundle.Platform) > 64 {
		return fmt.Errorf("support log metadata is too long")
	}
	if len(bundle.Files) == 0 {
		return fmt.Errorf("support log bundle is empty")
	}
	if len(bundle.Files) > maxSupportLogFiles {
		return fmt.Errorf("support log bundle contains too many files")
	}
	seen := make(map[string]struct{}, len(bundle.Files))
	for _, file := range bundle.Files {
		if file.Name != "p2wlan-daemon.log" && file.Name != "p2wlan-client.log" {
			return fmt.Errorf("unsupported support log file: %s", file.Name)
		}
		if _, ok := seen[file.Name]; ok {
			return fmt.Errorf("duplicate support log file: %s", file.Name)
		}
		seen[file.Name] = struct{}{}
		if len(file.Content) == 0 {
			return fmt.Errorf("support log file is empty: %s", file.Name)
		}
		if len(file.Content) > maxSupportLogExpandedBytes {
			return fmt.Errorf("support log file is too large: %s", file.Name)
		}
	}
	return nil
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
	tmp, err := os.CreateTemp(directory, ".p2wlan-log-*.tmp")
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
