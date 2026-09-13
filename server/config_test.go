package main

import "testing"

func TestControlBindConfiguration(t *testing.T) {
	t.Setenv("CONTROL_BIND", "")
	t.Setenv("PORT", "18080")
	if got, err := controlBindAddress(); err != nil || got != ":18080" {
		t.Fatalf("%s %v", got, err)
	}
	t.Setenv("CONTROL_BIND", "127.0.0.1:19000")
	if got, err := controlBindAddress(); err != nil || got != "127.0.0.1:19000" {
		t.Fatalf("%s %v", got, err)
	}
	for _, bad := range []string{"localhost", "127.0.0.1:abc", ":0", ":65536"} {
		t.Setenv("CONTROL_BIND", bad)
		if _, err := controlBindAddress(); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
