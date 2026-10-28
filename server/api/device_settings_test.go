package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

func TestUpdateDeviceSettingsAreAtomic(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "device-settings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	user, err := db.CreateUser("settings@example.test", "hash")
	if err != nil {
		t.Fatal(err)
	}
	device, err := db.CreateDevice(user.ID, "default", "settings-key", "original-name", "linux", "")
	if err != nil {
		t.Fatal(err)
	}
	other, err := db.CreateDevice(user.ID, "default", "other-key", "other", "linux", "")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(nil, nil, db)
	for _, ip := range []string{"invalid", "192.0.2.12", other.VirtualIP} {
		r := httptest.NewRequest(http.MethodPatch, "/api/v1/devices/"+device.ID, strings.NewReader(`{"device_name":"new-name","virtual_ip":"`+ip+`"}`))
		r.SetPathValue("id", device.ID)
		r = r.WithContext(context.WithValue(r.Context(), auth.UserClaimsKey, &auth.Claims{UserID: user.ID}))
		w := httptest.NewRecorder()
		s.UpdateDevice(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("IP %q: HTTP %d: %s", ip, w.Code, w.Body.String())
		}
		current, err := db.GetDevice(device.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.DeviceName != device.DeviceName || current.VirtualIP != device.VirtualIP {
			t.Fatalf("failed PATCH partially committed: %+v", current)
		}
	}
	// A valid combined request commits both settings together.
	r := httptest.NewRequest(http.MethodPatch, "/api/v1/devices/"+device.ID, strings.NewReader(`{"device_name":"new-name","virtual_ip":"10.20.0.50"}`))
	r.SetPathValue("id", device.ID)
	r = r.WithContext(context.WithValue(r.Context(), auth.UserClaimsKey, &auth.Claims{UserID: user.ID}))
	w := httptest.NewRecorder()
	s.UpdateDevice(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("valid combined PATCH: HTTP %d: %s", w.Code, w.Body.String())
	}
	current, err := db.GetDevice(device.ID)
	if err != nil || current.DeviceName != "new-name" || current.VirtualIP != "10.20.0.50" {
		t.Fatalf("combined PATCH missing values: device=%+v err=%v", current, err)
	}
}
