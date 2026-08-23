package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/yhan-sun/p2wlan/server/auth"
)

func TestUploadSupportLogsStoresCompressedPrivateBundle(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("LOG_UPLOAD_DIR", directory)
	server := NewServer(nil, nil, nil)

	bundle := supportLogBundle{
		SchemaVersion: supportLogSchemaVersion,
		UploadedAt:    "2026-08-23T08:00:00Z",
		DeviceName:    "Mini",
		Platform:      "macos",
		Files: []supportLogBundleFile{{
			Name:    "p2wlan-daemon.log",
			Content: "direct_path_degraded\n",
		}},
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var body bytes.Buffer
	writer := gzip.NewWriter(&body)
	if _, err := writer.Write(encoded); err != nil {
		t.Fatalf("gzip.Write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip.Close: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/support/logs", &body)
	req.Header.Set("Content-Encoding", "gzip")
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{
		UserID: "user-1",
	}))
	recorder := httptest.NewRecorder()
	server.UploadSupportLogs(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("UploadSupportLogs: HTTP %d %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Success  bool   `json:"success"`
		UploadID string `json:"upload_id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.Success || len(response.UploadID) != 24 {
		t.Fatalf("unexpected response: %+v", response)
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || filepath.Ext(entries[0].Name()) != ".gz" {
		t.Fatalf("expected one gzip upload, got %+v", entries)
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("upload permissions = %o, want 600", info.Mode().Perm())
	}

	storedFile, err := os.Open(filepath.Join(directory, entries[0].Name()))
	if err != nil {
		t.Fatalf("Open upload: %v", err)
	}
	decompressed, err := gzip.NewReader(storedFile)
	if err != nil {
		t.Fatalf("stored gzip: %v", err)
	}
	storedBytes, err := io.ReadAll(decompressed)
	if err != nil {
		t.Fatalf("Read stored gzip: %v", err)
	}
	_ = decompressed.Close()
	_ = storedFile.Close()
	var stored storedSupportLogBundle
	if err := json.Unmarshal(storedBytes, &stored); err != nil {
		t.Fatalf("decode stored bundle: %v", err)
	}
	if stored.UploadID != response.UploadID || stored.UserID != "user-1" ||
		stored.Bundle.Files[0].Content != "direct_path_degraded\n" {
		t.Fatalf("unexpected stored bundle: %+v", stored)
	}
}

func TestUploadSupportLogsRejectsDeviceCredentials(t *testing.T) {
	server := NewServer(nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/support/logs", bytes.NewReader(nil))
	req.Header.Set("Content-Encoding", "gzip")
	req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
		UserID: "user-1",
	}))
	recorder := httptest.NewRecorder()
	server.UploadSupportLogs(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("device credential accepted: HTTP %d", recorder.Code)
	}
}
