package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/internal/privatefile"
)

func TestUploadSupportLogsStoresCompressedPrivateBundle(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("LOG_UPLOAD_DIR", directory)
	server := NewServer(nil, nil, nil)

	bundle := supportLogBundle{
		SchemaVersion: supportLogSchemaVersion1,
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
		Success   bool   `json:"success"`
		UploadID  string `json:"upload_id"`
		Instances int    `json:"instances"`
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
	if err := privatefile.Verify(filepath.Join(directory, entries[0].Name())); err != nil {
		t.Fatalf("upload access is not private: %v", err)
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

func TestUploadSupportLogsV2WithRoomInstances(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("LOG_UPLOAD_DIR", directory)
	server := NewServer(nil, nil, nil)

	roomHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	bundle := supportLogBundle{
		SchemaVersion: supportLogSchemaVersion2,
		UploadedAt:    "2026-09-09T08:00:00Z",
		DeviceName:    "MacBook",
		Platform:      "macos",
		Manifest: &supportLogManifest{
			TotalInstances: 2,
			NetworkIDs:     []string{"net-main", "room-123"},
			HasRoomLogs:    true,
		},
		Instances: []supportLogInstance{
			{
				InstanceType:  "main",
				NetworkID:     "net-main",
				BootID:        "boot-1",
				Log:           "main daemon log\n",
				StatusSummary: `{"virtual_ip":"10.20.0.1"}`,
			},
			{
				InstanceType:  "room",
				NetworkID:     "room-123",
				ProfileID:     roomHex,
				BootID:        "boot-2",
				Log:           "room daemon log\n",
				StatusSummary: `{"virtual_ip":"10.20.1.2"}`,
			},
		},
		Files: []supportLogBundleFile{
			{
				Name:    "p2wlan-daemon.log",
				Content: "main log file\n",
			},
			{
				Name:    "rooms/" + roomHex + "/p2wlan-room.log",
				Content: "room log file\n",
			},
		},
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
		UserID: "user-v2",
	}))
	recorder := httptest.NewRecorder()
	server.UploadSupportLogs(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("UploadSupportLogs v2: HTTP %d %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Success   bool   `json:"success"`
		UploadID  string `json:"upload_id"`
		Instances int    `json:"instances"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.Success || response.Instances != 2 {
		t.Fatalf("unexpected v2 response: %+v", response)
	}
}

func TestUploadSupportLogsV2WithInstancesOnly(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("LOG_UPLOAD_DIR", directory)
	server := NewServer(nil, nil, nil)
	roomHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	bundle := supportLogBundle{
		SchemaVersion: supportLogSchemaVersion2,
		UploadedAt:    "2026-09-09T08:00:00Z",
		DeviceName:    "linux-cli",
		Platform:      "linux-cli",
		Manifest: &supportLogManifest{
			TotalInstances:        2,
			HasRoomLogs:           true,
			RetainedRoomInstances: 1,
		},
		Instances: []supportLogInstance{
			{InstanceType: "main", NetworkID: "default", Log: "main\n"},
			{InstanceType: "room", NetworkID: "room-1", ProfileID: roomHex, Log: "room\n"},
		},
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	zw := gzip.NewWriter(&body)
	if _, err := zw.Write(encoded); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/support/logs", &body)
	req.Header.Set("Content-Encoding", "gzip")
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{UserID: "cli-user"}))
	recorder := httptest.NewRecorder()
	server.UploadSupportLogs(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("instances-only bundle: HTTP %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestUploadSupportLogsRejectsInvalidFileNameOrTraversal(t *testing.T) {
	server := NewServer(nil, nil, nil)
	tests := []struct {
		name          string
		schemaVersion int
		fileName      string
	}{
		{"traversal in v1", supportLogSchemaVersion1, "../../etc/passwd"},
		{"room file in v1", supportLogSchemaVersion1, "p2wlan-room.log"},
		{"traversal in v2", supportLogSchemaVersion2, "rooms/../../p2wlan-room.log"},
		{"invalid profile_id in v2", supportLogSchemaVersion2, "rooms/short/p2wlan-room.log"},
		{"arbitrary file in v2", supportLogSchemaVersion2, "arbitrary.log"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bundle := supportLogBundle{
				SchemaVersion: tc.schemaVersion,
				UploadedAt:    "2026-09-09T08:00:00Z",
				DeviceName:    "Device",
				Platform:      "macos",
				Files: []supportLogBundleFile{{
					Name:    tc.fileName,
					Content: "content\n",
				}},
			}
			encoded, _ := json.Marshal(bundle)
			var body bytes.Buffer
			writer := gzip.NewWriter(&body)
			_, _ = writer.Write(encoded)
			_ = writer.Close()

			req := httptest.NewRequest(http.MethodPost, "/api/v1/support/logs", &body)
			req.Header.Set("Content-Encoding", "gzip")
			req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{
				UserID: "user-1",
			}))
			recorder := httptest.NewRecorder()
			server.UploadSupportLogs(recorder, req)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("expected Bad Request for %s, got HTTP %d", tc.name, recorder.Code)
			}
		})
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

func TestUploadSupportLogsV2CountsEachRoomOnce(t *testing.T) {
	t.Setenv("LOG_UPLOAD_DIR", t.TempDir())
	server := NewServer(nil, nil, nil)
	roomHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	bundle := supportLogBundle{
		SchemaVersion: 2, DeviceName: "review", Platform: "macos",
		Manifest: &supportLogManifest{TotalInstances: 2, HasRoomLogs: true},
		Files: []supportLogBundleFile{
			{Name: "p2wlan-daemon.log", Content: "main"},
			{Name: "rooms/" + roomHex + "/p2wlan-daemon.log", Content: "room"},
			{Name: "rooms/" + roomHex + "/status-summary.json", Content: "{}"},
		},
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	zw := gzip.NewWriter(&body)
	if _, err := zw.Write(encoded); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/support/logs", &body)
	req.Header.Set("Content-Encoding", "gzip")
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{UserID: "review"}))
	rec := httptest.NewRecorder()
	server.UploadSupportLogs(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Instances int `json:"instances"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Instances != 2 {
		t.Fatalf("one main daemon and one room must be 2 instances, got %d", response.Instances)
	}
}

func TestUploadSupportLogsRejectsManifestTotalInstancesMismatch(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("LOG_UPLOAD_DIR", directory)
	server := NewServer(nil, nil, nil)
	roomHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	bundle := supportLogBundle{
		SchemaVersion: 2, DeviceName: "review", Platform: "macos",
		Manifest: &supportLogManifest{TotalInstances: 5, HasRoomLogs: true},
		Files: []supportLogBundleFile{
			{Name: "p2wlan-daemon.log", Content: "main"},
			{Name: "rooms/" + roomHex + "/p2wlan-daemon.log", Content: "room"},
		},
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	zw := gzip.NewWriter(&body)
	if _, err := zw.Write(encoded); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/support/logs", &body)
	req.Header.Set("Content-Encoding", "gzip")
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{UserID: "review"}))
	rec := httptest.NewRecorder()
	server.UploadSupportLogs(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 for manifest mismatch, got HTTP %d: %s", rec.Code, rec.Body.String())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected bundle was persisted: %+v", entries)
	}
}

func TestUploadSupportLogsV2AcceptsFiveAndEightRoomBundles(t *testing.T) {
	for _, roomCount := range []int{5, 8} {
		t.Run(fmt.Sprintf("%d rooms", roomCount), func(t *testing.T) {
			directory := t.TempDir()
			t.Setenv("LOG_UPLOAD_DIR", directory)
			server := NewServer(nil, nil, nil)
			bundle := supportLogBundleForRooms(roomCount)
			recorder := postSupportLogBundle(t, server, bundle)
			if recorder.Code != http.StatusOK {
				t.Fatalf("%d room bundle (%d files): HTTP %d %s", roomCount, len(bundle.Files), recorder.Code, recorder.Body.String())
			}
			var response struct {
				Success   bool `json:"success"`
				Instances int  `json:"instances"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if !response.Success || response.Instances != roomCount+1 {
				t.Fatalf("unexpected response: %+v", response)
			}
		})
	}
}

func TestUploadSupportLogsV2RejectsMoreThanDefaultRoomBudget(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("LOG_UPLOAD_DIR", directory)
	server := NewServer(nil, nil, nil)
	recorder := postSupportLogBundle(t, server, supportLogBundleForRooms(9))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 9 room bundle to be rejected, got HTTP %d: %s", recorder.Code, recorder.Body.String())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected bundle was persisted: %+v", entries)
	}
}

func TestUploadSupportLogsV2RejectsMultipleLogsForOneRoom(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("LOG_UPLOAD_DIR", directory)
	server := NewServer(nil, nil, nil)
	profileID := fmt.Sprintf("%064x", 1)
	bundle := supportLogBundle{
		SchemaVersion: supportLogSchemaVersion2,
		DeviceName:    "support-test",
		Platform:      "macos",
		Manifest: &supportLogManifest{
			TotalInstances: 2,
			HasRoomLogs:    true,
		},
		Files: []supportLogBundleFile{
			{Name: "p2wlan-daemon.log", Content: "main daemon log\n"},
			{Name: "rooms/" + profileID + "/p2wlan-daemon.log", Content: "new room log\n"},
			{Name: "rooms/" + profileID + "/p2wlan-room.log", Content: "legacy room log\n"},
		},
	}
	recorder := postSupportLogBundle(t, server, bundle)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected duplicate room logs to be rejected, got HTTP %d: %s", recorder.Code, recorder.Body.String())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected bundle was persisted: %+v", entries)
	}
}

func TestUploadSupportLogsV2RecordsOmittedRoomInstances(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("LOG_UPLOAD_DIR", directory)
	server := NewServer(nil, nil, nil)
	bundle := supportLogBundleForRooms(maxSupportLogRoomInstances)
	bundle.Manifest.OmittedRoomInstances = 1
	bundle.Manifest.OmittedReason = "room_instance_budget"
	recorder := postSupportLogBundle(t, server, bundle)
	if recorder.Code != http.StatusOK {
		t.Fatalf("omitted-room bundle: HTTP %d %s", recorder.Code, recorder.Body.String())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one stored bundle, got %+v", entries)
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
		t.Fatalf("Read stored bundle: %v", err)
	}
	_ = decompressed.Close()
	_ = storedFile.Close()
	var stored storedSupportLogBundle
	if err := json.Unmarshal(storedBytes, &stored); err != nil {
		t.Fatalf("decode stored bundle: %v", err)
	}
	if stored.Bundle.Manifest == nil ||
		stored.Bundle.Manifest.OmittedRoomInstances != 1 ||
		stored.Bundle.Manifest.OmittedReason != "room_instance_budget" {
		t.Fatalf("omitted-room metadata was not preserved: %+v", stored.Bundle.Manifest)
	}
}

func supportLogBundleForRooms(roomCount int) supportLogBundle {
	files := []supportLogBundleFile{
		{Name: "p2wlan-daemon.log", Content: "main daemon log\n"},
		{Name: "p2wlan-client.log", Content: "client log\n"},
	}
	for room := 1; room <= roomCount; room++ {
		profileID := fmt.Sprintf("%064x", room)
		files = append(files,
			supportLogBundleFile{
				Name:    "rooms/" + profileID + "/p2wlan-daemon.log",
				Content: "room daemon log\n",
			},
			supportLogBundleFile{
				Name:    "rooms/" + profileID + "/status-summary.json",
				Content: `{"phase":"unavailable"}`,
			},
		)
	}
	return supportLogBundle{
		SchemaVersion: supportLogSchemaVersion2,
		DeviceName:    "support-test",
		Platform:      "macos",
		Manifest: &supportLogManifest{
			TotalInstances:        roomCount + 1,
			HasRoomLogs:           true,
			RetainedRoomInstances: roomCount,
		},
		Files: files,
	}
}

func postSupportLogBundle(t *testing.T, server *Server, bundle supportLogBundle) *httptest.ResponseRecorder {
	t.Helper()
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
		UserID: "support-test",
	}))
	recorder := httptest.NewRecorder()
	server.UploadSupportLogs(recorder, req)
	return recorder
}
